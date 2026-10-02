"""install.sh's agent-file block (the pcdn_agent package + the pcdn-agent launcher), run into a
temporary root: a fresh install, an --upgrade over the former single-file agent and over an older
package (a module it no longer has must not linger), and the installed launcher's subcommands."""

import os
import pathlib
import runpy
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
EDGE = HERE.parent


def install_block() -> str:
    text = (EDGE / "install.sh").read_text()
    return text.split("# >>> pcdn agent files", 1)[1].split("\n", 1)[1].split("# <<< pcdn agent files", 1)[0]


def run_block(root: pathlib.Path):
    block = install_block().replace("/usr/local/", f"{root}/usr/local/")
    subprocess.run(["bash", "-euo", "pipefail", "-c", block], check=True, env=dict(os.environ, HERE=str(EDGE)))


def sources(base: pathlib.Path) -> set:
    return {str(p.relative_to(base)) for p in base.rglob("*.py") if "__pycache__" not in p.parts}


def launcher(root, *args, **env):
    return subprocess.run([sys.executable, str(root / "usr/local/bin/pcdn-agent"), *args], capture_output=True,
                          text=True, env=dict(os.environ, PCDN_CONFIG="/nonexistent", **env), cwd="/")


def test_install_block_fresh_and_upgrade(tmp_path):
    root = tmp_path / "root"
    lib = root / "usr/local/lib/pcdn"
    # an edge still running the former single-file agent, plus a stale package from an older bundle
    (root / "usr/local/bin").mkdir(parents=True)
    (root / "usr/local/bin/pcdn-agent").write_text("#!/usr/bin/env python3\nraise SystemExit('old agent')\n")
    (lib / "pcdn_agent").mkdir(parents=True)
    (lib / "pcdn_agent/stale_module.py").write_text("raise ImportError('stale')\n")
    for _ in range(2):   # idempotent
        run_block(root)
        assert sources(lib / "pcdn_agent") == sources(EDGE / "pcdn_agent")
        assert not (lib / "pcdn_agent/stale_module.py").exists()
        assert sorted(p.name for p in lib.iterdir()) == ["pcdn_agent"]   # no .new / .old left behind
        assert (root / "usr/local/bin/pcdn-agent").read_bytes() == (EDGE / "pcdn-agent.py").read_bytes()
        assert os.stat(root / "usr/local/bin/pcdn-agent").st_mode & 0o777 == 0o755
        assert all(os.stat(lib / "pcdn_agent" / p).st_mode & 0o777 == 0o644 for p in sources(lib / "pcdn_agent"))
    assert list((lib / "pcdn_agent/render").glob("__pycache__/*.pyc"))   # pre-compiled

    p = launcher(root, "guard")
    assert p.returncode == 0, p.stderr
    assert "table inet pcdn_guard" in p.stdout
    p = launcher(root, "guard", "--synproxy")
    assert p.returncode == 0 and "synproxy" in p.stdout, p.stderr
    p = launcher(root, "origin-guard", PCDN_NGINX_USER="nobody")
    assert p.returncode == 0, p.stderr
    assert "table inet pcdn_origin_guard" in p.stdout
    p = launcher(root, "origin-guard", PCDN_NGINX_USER="root")   # refused, exit 1
    assert p.returncode == 1 and "NGINX_USER" in p.stderr
    p = launcher(root, "once")   # no controller configured: the loop refuses to start
    assert p.returncode == 1 and "CONTROLLER_URL and EDGE_TOKEN must be set" in p.stderr
    p = launcher(root, "bootstrap", PCDN_NGINX_DIR=str(tmp_path / "ngx"), PCDN_CACHE_DIR=str(tmp_path / "cache"),
                 PCDN_STATE_FILE=str(tmp_path / "state.json"), PCDN_NGINX_TEST_CMD="true", PCDN_NGINX_RELOAD_CMD="true",
                 # the assets install.sh puts in /usr/share/pcdn (absent on a CI runner)
                 PCDN_NJS_FILE=str(EDGE / "njs/pcdn.js"), PCDN_BASE_TEMPLATE=str(EDGE / "nginx/pcdn-base.conf"),
                 PCDN_PAGES_DIR=str(EDGE / "pages"))
    assert p.returncode == 0, p.stderr
    assert (tmp_path / "ngx/http.conf").is_file()


def test_installed_launcher_uses_the_installed_package(tmp_path):
    """The launcher imports pcdn_agent from ../lib/pcdn, never from somewhere else on sys.path; the
    imaged entry point imports (pcdn-imaged runs `pcdn-agent imaged`)."""
    root = tmp_path / "root"
    run_block(root)
    code = ("import runpy, sys\nsys.argv = ['pcdn-agent', 'guard']\n"
            f"runpy.run_path({str(root / 'usr/local/bin/pcdn-agent')!r}, run_name='__main__')\n"
            "import pcdn_agent, pcdn_agent.imaged\n"
            "print(pcdn_agent.__file__, file=sys.stderr)\n"
            "assert callable(pcdn_agent.imaged.run_imaged) and callable(pcdn_agent.imaged.imaged_server)\n")
    p = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, cwd="/",
                       env=dict(os.environ, PCDN_CONFIG="/nonexistent"))
    assert p.returncode == 0, p.stderr
    assert p.stderr.strip() == str(root / "usr/local/lib/pcdn/pcdn_agent/__init__.py")


def test_checkout_launcher_and_module_api():
    """edge/pcdn-agent.py runs from a checkout, and runpy / `python3 -m pcdn_agent` work too."""
    p = subprocess.run([sys.executable, str(EDGE / "pcdn-agent.py"), "guard"], capture_output=True, text=True,
                       env=dict(os.environ, PCDN_CONFIG="/nonexistent"), cwd="/")
    assert p.returncode == 0 and "table inet pcdn_guard" in p.stdout, p.stderr
    p = subprocess.run([sys.executable, "-m", "pcdn_agent", "guard"], capture_output=True, text=True,
                       env=dict(os.environ, PCDN_CONFIG="/nonexistent"), cwd=str(EDGE))
    assert p.returncode == 0 and "table inet pcdn_guard" in p.stdout, p.stderr
    ns = runpy.run_path(str(EDGE / "pcdn-agent.py"), run_name="pcdn_agent_runpy")
    assert callable(ns["render_all"]) and ns["DEFAULTS"]["NGINX_DIR"] == "/etc/nginx/pcdn"
