"""Golden-snapshot harness for the agent's rendering (not collected by pytest).

Replays a corpus of recorded calls (render_*, norm_*, site_js, redirect_maps, the regex checks, ...)
against an agent and stores / compares the exact results, so a refactor can prove byte-identical
output. The corpus is recorded from the test suite itself (every config the tests' builders produce):

    record-corpus:  PYTHONPATH=edge/tests PCDN_REC_OUT=corpus.pkl \
                    python3 -m pytest -p no:cacheprovider -p golden_recplug --basetemp=/tmp/pgr/t edge/tests
    snapshot:       PYTHONHASHSEED=0 python3 golden_render.py snapshot AGENT.py corpus.pkl golden.pkl.gz
    check:          PYTHONHASHSEED=0 python3 golden_render.py check AGENT.py corpus.pkl golden.pkl.gz

AGENT.py is any file that exposes the agent's names (edge/pcdn-agent.py, or an old single-file copy).
Run snapshot and check in the same environment (same nginx build, same --basetemp tree present; a
short --basetemp keeps the unix socket paths the e2e tests render under the 107-byte limit).
render_rev hashes the agent's own source and so differs whenever the code does, by design.
"""
import gzip
import hashlib
import importlib.util
import logging
import pickle
import sys


class _Capture(logging.Handler):
    """The agent's log lines are part of a call's observable behaviour: they are compared too."""

    def __init__(self):
        super().__init__(level=logging.DEBUG)
        self.lines = []

    def emit(self, record):
        self.lines.append(f"{record.levelname} {record.getMessage()}")


def load(path):
    spec = importlib.util.spec_from_file_location("golden_agent", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def replay(mod, corpus):
    out, skipped = {}, 0
    cap = _Capture()
    logger = logging.getLogger("pcdn-agent")
    logger.addHandler(cap)
    logger.propagate = False
    logger.setLevel(logging.DEBUG)
    for blob in corpus:
        key = hashlib.sha256(blob).hexdigest()
        try:
            name, args, kwargs = pickle.loads(blob)
        except Exception:  # noqa: BLE001 - arguments holding objects of a test-only module
            skipped += 1
            continue
        cap.lines = []
        try:
            res = ("ok", repr(getattr(mod, name)(*args, **kwargs)))
        except Exception as e:  # noqa: BLE001 - the exception itself is part of the behaviour
            res = ("raise", f"{type(e).__name__}: {e}")
        out[key] = (name, res + tuple(cap.lines))
    return out, skipped


def main(argv):
    mode, agent_path, corpus_path, golden = argv[1:5]
    with open(corpus_path, "rb") as f:
        corpus = pickle.load(f)
    results, skipped = replay(load(agent_path), corpus)
    if mode == "snapshot":
        with gzip.open(golden, "wb") as f:
            pickle.dump(results, f)
        print(f"snapshot: {len(results)} results ({skipped} skipped)")
        return 0
    with gzip.open(golden, "rb") as f:
        want = pickle.load(f)
    bad = [k for k in want if results.get(k) != want[k]]
    missing = set(want) - set(results)
    names = sorted({v[0] for v in want.values()})
    print(f"check: {len(want)} golden results over {len(names)} functions, {len(bad)} differ, "
          f"{len(missing)} missing, {skipped} skipped")
    for k in bad[:10]:
        print("DIFF", want[k][0], str(want[k][1])[:300], "\n  !=", str(results.get(k))[:300])
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
