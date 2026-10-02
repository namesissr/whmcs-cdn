"""Pasargad CDN edge agent (v2): command line.

Pulls site configuration from the controller, renders the nginx base config,
one vhost per proxied host and the njs data module (sites.js), installs
certificates, executes cache purges and reports per-host usage + security
events. Standard library only, so it runs on any stock Debian/Ubuntu python3.

    pcdn-agent            run the loop
    pcdn-agent once       one sync (config, purges, usage)
    pcdn-agent bootstrap  write an empty tree if none exists (used by install.sh
                          so nginx can start before the first sync)
    pcdn-agent imaged     loopback image transformer (images v2, service pcdn-imaged)
    pcdn-agent guard [--synproxy]
                          print the nftables host guard ruleset (install.sh --harden-net)
    pcdn-agent origin-guard
                          print the nftables origin guard ruleset (install.sh, default on)"""

import logging
import os
import signal
import sys

from .agent import Agent
from .apply import bootstrap
from .imaged import run_imaged
from .render.guards import render_guard, render_origin_guard
from .settings import AGENT_LOGS, load_config, log


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    # capture the agent's own WARN/ERROR lines so they ship with the nginx error log (SPEC §11.2)
    logging.getLogger("pcdn-agent").addHandler(AGENT_LOGS)
    try:
        cfg = load_config(os.getenv("PCDN_CONFIG", "/etc/pcdn/agent.conf"))
    except PermissionError:   # the sandboxed imaged cannot read a root-only file: defaults + env
        cfg = load_config("/nonexistent")
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "bootstrap":
        bootstrap(cfg)
        return
    if cmd == "imaged":   # SPEC §16.6 image transformer (service pcdn-imaged)
        run_imaged(cfg)
        return
    if cmd == "guard":    # SPEC §16.3: print the nftables ruleset (install.sh --harden-net)
        sys.stdout.write(render_guard(cfg, synproxy="--synproxy" in sys.argv[2:]))
        return
    if cmd == "origin-guard":   # print the connect-time origin guard ruleset (install.sh)
        try:
            sys.stdout.write(render_origin_guard(cfg))
        except ValueError as e:
            log.error("%s", e)
            sys.exit(1)
        return
    if not cfg["CONTROLLER_URL"] or not cfg["EDGE_TOKEN"]:
        log.error("CONTROLLER_URL and EDGE_TOKEN must be set in /etc/pcdn/agent.conf")
        sys.exit(1)
    agent = Agent(cfg)

    def stop(*_):
        agent.running = False

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    if cmd == "once":
        agent.tick()
        return
    agent.loop()
