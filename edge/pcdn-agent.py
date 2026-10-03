#!/usr/bin/env python3
"""Pasargad CDN edge agent (v2): the `pcdn-agent` command and the agent's flat module API.

The agent itself is the pcdn_agent package: next to this file in a checkout (edge/pcdn_agent/), in
../lib/pcdn/ on an installed edge (install.sh installs this file as /usr/local/bin/pcdn-agent and the
package as /usr/local/lib/pcdn/pcdn_agent/). See pcdn_agent/cli.py for the subcommands.

Run as a program it runs pcdn_agent.cli.main(). Loaded as a module (importlib, like the edge and
controller tests do) it exposes every name of the agent, as the former single-file agent did: each
load gets a fresh, private copy of the package (its own caches and buffers), and assigning a name on
the loaded module re-binds it inside that copy (pcdn_agent.AgentNamespace).
"""

import os
import sys

_HERE = os.path.dirname(os.path.realpath(__file__))
_LIB_DIRS = (_HERE, os.path.normpath(os.path.join(_HERE, "..", "lib", "pcdn")))


def _lib_dir() -> str:
    for d in _LIB_DIRS:
        if os.path.isfile(os.path.join(d, "pcdn_agent", "__init__.py")):
            return d
    sys.exit("pcdn-agent: the pcdn_agent package is missing (looked in %s)" % ", ".join(_LIB_DIRS))


def _load_private_copy() -> None:
    """Import the package under a unique name and take over its namespace (and module type)."""
    import gc
    import importlib.util
    import types

    pkg_dir = os.path.join(_lib_dir(), "pcdn_agent")
    n = 0
    while f"_pcdn_agent_{n}" in sys.modules:
        n += 1
    name = f"_pcdn_agent_{n}"
    spec = importlib.util.spec_from_file_location(name, os.path.join(pkg_dir, "__init__.py"),
                                                  submodule_search_locations=[pkg_dir])
    pkg = importlib.util.module_from_spec(spec)
    sys.modules[name] = pkg
    spec.loader.exec_module(pkg)
    g = globals()
    g.update({k: v for k, v in vars(pkg).items() if not (k.startswith("__") and k.endswith("__"))})
    # this module object: in sys.modules after a normal import, found through its namespace when
    # loaded with spec.loader.exec_module() alone
    me = sys.modules.get(__name__)
    if me is None or me.__dict__ is not g:
        me = next((r for r in gc.get_referrers(g) if isinstance(r, types.ModuleType) and r.__dict__ is g), None)
    if me is not None:
        me.__class__ = type(pkg)


if __name__ == "__main__":
    sys.path.insert(0, _lib_dir())
    from pcdn_agent.cli import main

    main()
else:
    _load_private_copy()
