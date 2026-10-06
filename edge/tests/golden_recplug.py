"""pytest plugin for golden_render.py: record the arguments of the agent's render / normalise functions
while the edge test suite runs (PCDN_REC_OUT=<corpus file>, -p golden_recplug)."""
import copy
import functools
import hashlib
import os
import pickle
import re
import types

OUT = os.environ["PCDN_REC_OUT"]
PAT = re.compile(r"^(render_\w+|_render_site|site_js|redirect_maps|norm_\w+|key_options|key_infos|preload_links|"
                 r"wildcard_re|regex_unsafe|pcre_regex|page_rules|image_signature|l4_sites|tree_digest|_legacy_sections|"
                 r"module_blocks|parse_nginx_v|with_cached_bot_ranges|classify_tunnel|log_record|anonymize_ip|redact|"
                 r"parse_error_lines|parse_image_spec|mtls_token|fair_hot|node_tag|origin_host_allowed|is_public_ip|"
                 r"guard_allow|logship_sites|video_hosts|_rd_matches|storage_log_repr|speed_locations|render_functions)$")
RECS = {}
_done = set()


def _wrap(mod):
    if id(mod) in _done:
        return
    _done.add(id(mod))
    for name, fn in list(vars(mod).items()):
        if not (isinstance(fn, types.FunctionType) and PAT.match(name)):
            continue

        def make(name, fn):
            @functools.wraps(fn)
            def w(*a, **k):
                try:
                    blob = pickle.dumps((name, copy.deepcopy(a), copy.deepcopy(k)))
                    RECS.setdefault(hashlib.sha256(blob).hexdigest(), blob)
                except Exception:
                    pass
                return fn(*a, **k)
            return w
        setattr(mod, name, make(name, fn))


def pytest_collection_modifyitems(session, config, items):
    for it in items:
        m = getattr(it, "module", None)
        for v in list(vars(m).values()) if m else []:
            if isinstance(v, types.ModuleType) and str(getattr(v, "__file__", "")).endswith("pcdn-agent.py"):
                _wrap(v)


def pytest_sessionfinish(session, exitstatus):
    with open(OUT, "wb") as f:
        pickle.dump(list(RECS.values()), f)
    print(f"\nrecorded {len(RECS)} calls -> {OUT}")
