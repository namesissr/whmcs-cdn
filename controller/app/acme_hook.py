"""Called by acme.sh (dnsapi/dns_pcdn.sh) to publish DNS-01 challenges on every nameserver.

    python -m app.acme_hook add _acme-challenge.example.com <value>
    python -m app.acme_hook rm  _acme-challenge.example.com <value>
"""

import sys

from . import pdns


def main(argv: list[str]) -> int:
    if len(argv) != 3 or argv[0] not in ("add", "rm"):
        print(__doc__, file=sys.stderr)
        return 2
    action, name, value = argv
    cluster = pdns.client()
    try:
        if action == "add":
            cluster.add_txt(name, value)
        else:
            cluster.remove_txt(name, value)
    except Exception as e:  # noqa: BLE001
        print(f"acme hook {action} failed: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
