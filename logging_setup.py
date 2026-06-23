"""Structlog configuration for the autopilot MCP.

Mirrors tasque's src/tasque/logging_config.py so the audit trail can be
piped through the same log tooling. All output goes to stderr because the
MCP's stdio transport owns stdout.

Call configure() once at server startup.
"""

from __future__ import annotations

import logging
import os
import sys

import structlog
from structlog.typing import Processor


def _env_bool(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


def configure(
    *,
    json_format: bool | None = None,
    level: str | int | None = None,
) -> None:
    """Set up structlog routing to stderr. Idempotent."""
    if json_format is None:
        json_format = _env_bool("TASQUE_LOG_JSON")

    resolved_level: int
    if level is None:
        resolved_level = getattr(
            logging, os.environ.get("TASQUE_LOG_LEVEL", "INFO").upper(), logging.INFO
        )
    elif isinstance(level, str):
        resolved_level = getattr(logging, level.upper(), logging.INFO)
    else:
        resolved_level = level

    shared_processors: list[Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.UnicodeDecoder(),
    ]

    if json_format:
        renderer: Processor = structlog.processors.JSONRenderer()
        shared_processors.append(structlog.processors.format_exc_info)
    else:
        renderer = structlog.dev.ConsoleRenderer(colors=sys.stderr.isatty())

    structlog.configure(
        processors=[
            *shared_processors,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=shared_processors,
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            renderer,
        ],
    )

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(formatter)
    handler.set_name("autopilot.structlog")

    root = logging.getLogger()
    root.handlers[:] = [h for h in root.handlers if h.get_name() != "autopilot.structlog"]
    root.handlers.append(handler)
    root.setLevel(resolved_level)
