"""Pasargad CDN edge agent (v2). Standard library only (Python 3.12, Ubuntu 24.04).

Modules, lowest layer first (a module imports only from modules listed before it):

    settings            agent.conf defaults, load_config, logger, asset paths
    common              SAFE_* patterns, protocol constants, quoting / bounded-int helpers
    capabilities        nginx -V capabilities, dynamic modules, template @if blocks
    reload              tree digests, /__pcdn/confver reload verification
    validation.origin   origin address policy, pools, tunnels
    validation.storage  object-storage origins
    validation.regex    customer regex safety (parity with the controller)
    validation.rules    page rules, cache keys, redirects, transforms, bots, mTLS pulls, images, video
    validation.gates    visitor gates: waiting room and access apps (SPEC §18.1, §18.2)
    usage               access-log usage, tunnel quality, live aggregates, L4 usage
    functions           edge functions glue (pcdn-fn): routes, code bundle, status, usage
    render.stream       L4 apps and the stream {} config
    render.guards       nftables host guard and origin guard
    render.shield       origin shield
    render.http         http.conf, resizer, mTLS resizer, bots.conf, node block
    render.njs          sites.js entries
    render.site         per-site vhosts
    render.probe        synthetic tunnel probe servers + their certificate / body files (SPEC §22.3)
    render.tree         the whole rendered tree
    logship             log export
    nodelogs            centralized node logs
    tuning              kernel tuning profile and its runtime check (SPEC §22.6)
    heartbeat           metrics, the capabilities object, reload metrics and the memory guard
    probe               tunnel probe clients, echo origin and probe thread (SPEC §22.3)
    tcphealth           TCP health checks of pool members (SPEC §22.4)
    purge               cache purges
    apply               write / test / reload / roll back, bootstrap, origin guard peers
    controller          controller API client
    drain               node drain: state lock, flag, drain / undrain commands (SPEC §22.1)
    upgrade             self-upgrade to a target release, installed release (SPEC §23.1 / §23.2)
    imaged              `pcdn-agent imaged` image transformer
    agent               the Agent loop
    cli                 `pcdn-agent` command line

The package namespace also exposes every name of every module: the API of the former single-file
agent (edge/pcdn-agent.py re-exports it for the edge and controller tests). Assigning such a name on
the package (e.g. monkeypatch.setattr(pcdn_agent, "MAX_EVENTS", 3)) re-binds it in every module
that holds the same object, so the change is seen everywhere, as it was in the single module.
"""

import importlib
import sys
import types

# every module, lowest layer first (as in the table above)
_MODULE_NAMES = ("settings", "common", "capabilities", "reload", "validation.origin", "validation.storage",
                 "validation.regex", "validation.rules", "validation.gates", "usage", "functions", "render.stream",
                 "render.guards", "render.shield", "render.http", "render.njs", "render.site", "render.probe", "render.tree",
                 "logship", "nodelogs", "tuning", "heartbeat", "probe", "tcphealth", "purge", "apply", "controller",
                 "drain", "upgrade", "imaged", "agent", "cli")
_MODULES = tuple(importlib.import_module(f"{__name__}.{m}") for m in _MODULE_NAMES)
_MISSING = object()


class AgentNamespace(types.ModuleType):
    """Module type of the flat agent namespace: assigning or deleting a name forwards to every
    module in _MODULES that binds the same object under that name."""

    def _forward(self, name: str, value=_MISSING) -> None:
        old = self.__dict__.get(name, _MISSING)
        if old is _MISSING or (name.startswith("__") and name.endswith("__")):
            return
        for m in self.__dict__.get("_MODULES", ()):
            if m.__dict__.get(name, _MISSING) is old:
                if value is _MISSING:
                    del m.__dict__[name]
                else:
                    m.__dict__[name] = value

    def __setattr__(self, name, value):
        self._forward(name, value)
        super().__setattr__(name, value)

    def __delattr__(self, name):
        self._forward(name)
        super().__delattr__(name)


def _flat_namespace() -> dict:
    ns: dict = {}
    for m in _MODULES:
        for k, v in vars(m).items():
            if k.startswith("__") and k.endswith("__"):
                continue
            if k in ns and ns[k] is not v:
                raise ImportError(f"pcdn_agent: {k!r} is bound to different objects in two modules")
            ns[k] = v
    return ns


globals().update(_flat_namespace())
sys.modules[__name__].__class__ = AgentNamespace
