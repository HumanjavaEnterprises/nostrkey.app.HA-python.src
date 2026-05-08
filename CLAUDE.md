# NostrKey for Hermes — dev context

This is the **Hermes Agent** build of nostrkey. Sibling repo:
`~/development/nostrkey.app.OC-python.src` (the OpenClaw build, which
publishes `pip install nostrkey`).

## What this repo is

A Hermes plugin (per the `plugins/` shape: `plugin.yaml` manifest +
`__init__.py` with `register(ctx)` + `tools.py` with handlers) that
exposes the `nostrkey` library as five agent tools.

The bundled `nostrkey/` directory is a vendored copy of the core
library from the OC repo. Bugfixes that touch crypto must be applied
to both repos until/unless we collapse to a single source of truth.

## Layout

```
nostrkey.app.HA-python.src/
├── plugin.yaml              # Hermes manifest
├── __init__.py              # register(ctx) — adds plugin dir to sys.path, then registers tools
├── tools.py                 # Schemas + handlers (5 tools)
├── after-install.md         # Shown after `hermes plugins install`
├── nostrkey/                # Vendored core lib (mirror of OC repo's src/nostrkey/)
├── README.md
├── LICENSE
└── CLAUDE.md                # This file
```

## Why sys.path manipulation in __init__.py?

Hermes loads the plugin via `importlib.util.spec_from_file_location`
under namespace `_NS_PARENT.<slug>` with `__path__ = [plugin_dir]`. The
vendored `nostrkey/` package's internal absolute imports
(`from nostrkey.keys import ...`) need `plugin_dir` on `sys.path` to
resolve. The 4-line shim at the top of `__init__.py` does that.

If we ever move to relative imports throughout the vendored package,
the shim can go.

## Handler kwargs convention

Hermes's tool dispatcher injects `task_id`, `user_task`, and
sometimes `parent_agent` into every handler call. All handlers in
this plugin accept `(args, **kw)` to swallow them — match the
in-tree convention even though the dispatcher is now tolerant.

The dispatcher tolerance is real: `HumanjavaEnterprises/hermes-agent`
PR #1 (merged 2026-05-08, commit `dcc43ef6`) added
`_filter_kwargs_for_handler` so naive `def handler(args)` signatures
no longer raise `TypeError`. But every bundled plugin uses `**kw`;
keep that convention here. Upstream `NousResearch/hermes-agent` PR
not yet opened.

## Tool surface

Module-level singleton holds the current identity for the session; tools
share it. No auto-load on plugin init — the agent must call `generate`
or `load` explicitly.

## Page

User-facing landing page is at https://loginwithnostr.com/hermes (sibling
to /openclaw). Source: `~/development/loginwithnostr.web.landingpage.src/docs/hermes/`.
