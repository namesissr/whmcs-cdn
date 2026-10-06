"""The pcdn_agent package layout and the flat module API of edge/pcdn-agent.py."""

import ast
import importlib.util
import pathlib

HERE = pathlib.Path(__file__).resolve().parent
PKG = HERE.parent / "pcdn_agent"


def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE.parent / "pcdn-agent.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def module_names() -> tuple:
    tree = ast.parse((PKG / "__init__.py").read_text())
    for node in tree.body:
        if isinstance(node, ast.Assign) and node.targets[0].id == "_MODULE_NAMES":
            return ast.literal_eval(node.value)
    raise AssertionError("_MODULE_NAMES not found")


def test_every_module_is_listed_and_imports_only_lower_layers():
    names = module_names()
    on_disk = {str(p.relative_to(PKG).with_suffix("")).replace("/", ".") for p in PKG.rglob("*.py")
               if "__pycache__" not in p.parts and p.name not in ("__init__.py", "__main__.py")}
    assert set(names) == on_disk and len(names) == len(on_disk)
    for i, name in enumerate(names):
        path = PKG.joinpath(*name.split(".")).with_suffix(".py")
        pkg_parts = name.split(".")[:-1]
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.ImportFrom) and node.level:
                base = pkg_parts[:len(pkg_parts) - (node.level - 1)]
                target = ".".join(base + ([node.module] if node.module else []))
                assert target in names[:i], f"{name} imports {target}: not a lower layer"
            if isinstance(node, ast.Import):   # stdlib only, never the package by absolute name
                assert not any(a.name.split(".")[0] == "pcdn_agent" for a in node.names), name


def test_flat_api_assignment_reaches_the_defining_module(monkeypatch):
    a = load("agent_pkg_t1")
    agent_mod = a._MODULES[a._MODULE_NAMES.index("agent")]
    common = a._MODULES[a._MODULE_NAMES.index("common")]
    monkeypatch.setattr(a, "MAX_EVENTS", 3)   # defined in common, used by agent
    assert agent_mod.MAX_EVENTS == 3 and common.MAX_EVENTS == 3 and a.MAX_EVENTS == 3
    monkeypatch.setattr(a, "apply_config", lambda *x, **k: None)
    assert agent_mod.apply_config is a.apply_config
    monkeypatch.undo()
    assert agent_mod.MAX_EVENTS == 2000 and common.MAX_EVENTS == 2000 and a.MAX_EVENTS == 2000
    assert agent_mod.apply_config is a._MODULES[a._MODULE_NAMES.index("apply")].apply_config


def test_each_load_is_a_private_copy():
    a, b = load("agent_pkg_t2"), load("agent_pkg_t3")
    assert a.render_all is not b.render_all and a._CAPS_CACHE is not b._CAPS_CACHE
    assert a.AGENT_LOGS is not b.AGENT_LOGS
    a.MAX_ITEMS = 1
    assert b.MAX_ITEMS == 20000
