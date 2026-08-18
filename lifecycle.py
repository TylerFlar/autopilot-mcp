"""Keep autopilot browsers from outliving their session (Windows).

Observed leak, 2026-08-14: six MCP client sessions spanning four days each held an
autopilot server whose Camoufox trees stayed open forever — nothing ever closed
an idle context, and a server that dies uncleanly leaves the playwright driver
and every camoufox.exe running (they are not in the parent's kill tree). Three
mechanisms, all cheap:

1. ``adopt_kill_on_close_job()`` — put this process in a Job Object marked
   KILL_ON_JOB_CLOSE. Every descendant (playwright node driver, camoufox and
   its content processes) dies with this process, however it dies.
2. ``watch_ancestors()`` — a daemon thread waits on the parent and grandparent
   process handles (the wrapper python and the MCP client); when either exits,
   ``os._exit(0)`` — and the job object takes the browsers down.
3. ``force_exit_after(seconds)`` — armed after the MCP transport closes so a
   graceful shutdown that wedges (stuck Playwright IPC, hanging atexit) still
   terminates. Idle-profile reaping lives in ``browser.BrowserManager``.

Everything degrades to a no-op off Windows or on API failure — these are
backstops, never a reason the server fails to start.
"""

from __future__ import annotations

import ctypes
import os
import sys
import threading
from ctypes import wintypes

_JOB_HANDLE = None  # keep alive for the life of the process

_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000
_JobObjectExtendedLimitInformation = 9
_SYNCHRONIZE = 0x00100000
_TH32CS_SNAPPROCESS = 0x2
_INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value


class _IO_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("ReadOperationCount", ctypes.c_uint64),
        ("WriteOperationCount", ctypes.c_uint64),
        ("OtherOperationCount", ctypes.c_uint64),
        ("ReadTransferCount", ctypes.c_uint64),
        ("WriteTransferCount", ctypes.c_uint64),
        ("OtherTransferCount", ctypes.c_uint64),
    ]


class _JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_int64),
        ("PerJobUserTimeLimit", ctypes.c_int64),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    ]


class _JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", _JOBOBJECT_BASIC_LIMIT_INFORMATION),
        ("IoInfo", _IO_COUNTERS),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


class _PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", ctypes.c_wchar * 260),
    ]


def _kernel32():
    if not sys.platform.startswith("win"):
        return None
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    # Without prototypes ctypes treats HANDLEs as 32-bit c_int, truncating
    # 64-bit handles (GetCurrentProcess()'s -1 pseudo-handle arrives mangled
    # and AssignProcessToJobObject fails with ERROR_INVALID_HANDLE).
    k32.CreateJobObjectW.restype = wintypes.HANDLE
    k32.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
    k32.SetInformationJobObject.restype = wintypes.BOOL
    k32.SetInformationJobObject.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    k32.AssignProcessToJobObject.restype = wintypes.BOOL
    k32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    k32.GetCurrentProcess.restype = wintypes.HANDLE
    k32.GetCurrentProcess.argtypes = []
    k32.CloseHandle.restype = wintypes.BOOL
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    k32.OpenProcess.restype = wintypes.HANDLE
    k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    k32.WaitForMultipleObjects.restype = wintypes.DWORD
    k32.WaitForMultipleObjects.argtypes = [
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
        wintypes.BOOL,
        wintypes.DWORD,
    ]
    k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    k32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    k32.Process32FirstW.restype = wintypes.BOOL
    k32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(_PROCESSENTRY32W)]
    k32.Process32NextW.restype = wintypes.BOOL
    k32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(_PROCESSENTRY32W)]
    return k32


def adopt_kill_on_close_job() -> bool:
    """Assign this process to a kill-on-close job so children die with it."""
    global _JOB_HANDLE
    k32 = _kernel32()
    if k32 is None:
        return False
    try:
        job = k32.CreateJobObjectW(None, None)
        if not job:
            return False
        info = _JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        info.BasicLimitInformation.LimitFlags = _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        ok = k32.SetInformationJobObject(
            job,
            _JobObjectExtendedLimitInformation,
            ctypes.byref(info),
            ctypes.sizeof(info),
        )
        if not ok:
            k32.CloseHandle(job)
            return False
        if not k32.AssignProcessToJobObject(job, k32.GetCurrentProcess()):
            k32.CloseHandle(job)
            return False
        _JOB_HANDLE = job
        return True
    except Exception:
        return False


def _ancestor_pids(levels: int = 2) -> list[int]:
    """Parent (the MCP wrapper) and grandparent (the MCP client), via Toolhelp."""
    k32 = _kernel32()
    if k32 is None:
        return []
    parents: dict[int, int] = {}
    snapshot = k32.CreateToolhelp32Snapshot(_TH32CS_SNAPPROCESS, 0)
    if not snapshot or snapshot == _INVALID_HANDLE_VALUE:
        return []
    try:
        entry = _PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(entry)
        if k32.Process32FirstW(snapshot, ctypes.byref(entry)):
            while True:
                parents[int(entry.th32ProcessID)] = int(entry.th32ParentProcessID)
                if not k32.Process32NextW(snapshot, ctypes.byref(entry)):
                    break
    finally:
        k32.CloseHandle(snapshot)
    ancestors: list[int] = []
    pid = os.getpid()
    for _ in range(levels):
        pid = parents.get(pid, 0)
        if not pid:
            break
        ancestors.append(pid)
    return ancestors


def watch_ancestors() -> bool:
    """Exit (and so kill the browser job) the moment an ancestor process dies."""
    k32 = _kernel32()
    if k32 is None:
        return False
    handles = []
    for pid in _ancestor_pids():
        handle = k32.OpenProcess(_SYNCHRONIZE, False, pid)
        if handle:
            handles.append(handle)
    if not handles:
        return False

    def _wait() -> None:
        array = (wintypes.HANDLE * len(handles))(*handles)
        # bWaitAll=False: any ancestor dying is reason enough to leave.
        k32.WaitForMultipleObjects(len(handles), array, False, 0xFFFFFFFF)
        os._exit(0)

    threading.Thread(target=_wait, name="ancestor-watch", daemon=True).start()
    return True


def force_exit_after(seconds: float) -> None:
    """Hard-exit backstop for a shutdown that hangs; job object reaps children."""

    def _bomb() -> None:
        import time

        time.sleep(seconds)
        os._exit(0)

    threading.Thread(target=_bomb, name="exit-bomb", daemon=True).start()
