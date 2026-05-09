"""nostrkey plugin for Hermes Agent.

Vendors the nostrkey library (sibling ``nostrkey/`` package) and exposes
five tools to the agent. The plugin is loaded by Hermes via
``importlib.util.spec_from_file_location`` against this file; we add the
plugin directory to ``sys.path`` so the bundled ``nostrkey`` package's
internal absolute imports resolve.
"""

from __future__ import annotations

import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from .tools import (  # noqa: E402
    NOSTRKEY_EXPORT_NSEC_SCHEMA,
    NOSTRKEY_EXPORT_SEED_PHRASE_SCHEMA,
    NOSTRKEY_GENERATE_SCHEMA,
    NOSTRKEY_LOAD_SCHEMA,
    NOSTRKEY_SAVE_SCHEMA,
    NOSTRKEY_SIGN_EVENT_SCHEMA,
    NOSTRKEY_WHOAMI_SCHEMA,
    handle_nostrkey_export_nsec,
    handle_nostrkey_export_seed_phrase,
    handle_nostrkey_generate,
    handle_nostrkey_load,
    handle_nostrkey_save,
    handle_nostrkey_sign_event,
    handle_nostrkey_whoami,
)

_TOOLS = (
    ("nostrkey_generate",           NOSTRKEY_GENERATE_SCHEMA,           handle_nostrkey_generate,           "🔑"),
    ("nostrkey_whoami",             NOSTRKEY_WHOAMI_SCHEMA,             handle_nostrkey_whoami,             "👤"),
    ("nostrkey_save",               NOSTRKEY_SAVE_SCHEMA,               handle_nostrkey_save,               "💾"),
    ("nostrkey_load",               NOSTRKEY_LOAD_SCHEMA,               handle_nostrkey_load,               "📂"),
    ("nostrkey_sign_event",         NOSTRKEY_SIGN_EVENT_SCHEMA,         handle_nostrkey_sign_event,         "✍️"),
    ("nostrkey_export_nsec",        NOSTRKEY_EXPORT_NSEC_SCHEMA,        handle_nostrkey_export_nsec,        "🔓"),
    ("nostrkey_export_seed_phrase", NOSTRKEY_EXPORT_SEED_PHRASE_SCHEMA, handle_nostrkey_export_seed_phrase, "📜"),
)


def register(ctx) -> None:
    for name, schema, handler, emoji in _TOOLS:
        ctx.register_tool(
            name=name,
            toolset="nostrkey",
            schema=schema,
            handler=handler,
            emoji=emoji,
        )
