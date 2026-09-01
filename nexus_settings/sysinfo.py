from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
VENV_DIR = PROJECT_ROOT / "nexusvenv"
OLLAMA_API = os.getenv("NEXUS_AI_OLLAMA_URL") or os.getenv("OLLAMA_HOST") or "http://localhost:11434"
if not OLLAMA_API.startswith("http"):
    OLLAMA_API = "http://" + OLLAMA_API


def human_size(num_bytes: int) -> str:
    if num_bytes is None:
        return "?"
    size = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.2f} {unit}" if unit not in ("B", "KB") else f"{size:.0f} {unit}"
        size /= 1024
    return f"{size:.2f} TB"


def dir_size(path: Path) -> int:
    total = 0
    if not path or not Path(path).exists():
        return 0
    for root, dirs, files in os.walk(path, onerror=lambda e: None):
        for name in files:
            fp = os.path.join(root, name)
            try:
                st = os.lstat(fp)
                if not os.path.islink(fp):
                    total += st.st_size
            except OSError:
                continue
    return total


def python_executable() -> str:
    candidate = VENV_DIR / "bin" / "python"
    if candidate.exists():
        return str(candidate)
    win = VENV_DIR / "Scripts" / "python.exe"
    if win.exists():
        return str(win)
    return sys.executable


def venv_writable() -> bool:
    site = VENV_DIR / "lib"
    target = site if site.exists() else VENV_DIR
    return target.exists() and os.access(target, os.W_OK)


def ollama_binary() -> str | None:
    return shutil.which("ollama")


def ollama_binary_size() -> int:
    exe = ollama_binary()
    if not exe:
        return 0
    try:
        real = os.path.realpath(exe)
        return os.path.getsize(real)
    except OSError:
        return 0


def ollama_models_size() -> int:
    return sum(m.get("size", 0) for m in ollama_models())


def storage_breakdown() -> list[dict]:
    items = []

    venv = dir_size(VENV_DIR) if VENV_DIR.exists() else 0

    project_all = dir_size(PROJECT_ROOT)
    project_wo_venv = max(0, project_all - venv)

    items.append({"label": "Project code & data", "bytes": project_wo_venv,
                  "note": str(PROJECT_ROOT)})
    items.append({"label": "Python environment (nexusvenv)", "bytes": venv,
                  "note": str(VENV_DIR) if VENV_DIR.exists() else "not present"})

    bin_size = ollama_binary_size()
    items.append({"label": "Ollama program", "bytes": bin_size,
                  "note": ollama_binary() or "not installed"})

    models = ollama_models()
    models_size = sum(m.get("size", 0) for m in models)
    items.append({"label": f"Ollama models ({len(models)})", "bytes": models_size,
                  "note": ", ".join(m.get("name", "?") for m in models) or "none"})

    return items


def pip_packages() -> list[dict]:
    exe = python_executable()
    try:
        out = subprocess.run(
            [exe, "-m", "pip", "list", "--format=json", "--disable-pip-version-check"],
            check=True, capture_output=True, text=True, timeout=60,
        )
        data = json.loads(out.stdout or "[]")
        return sorted(
            ({"name": p.get("name", "?"), "version": p.get("version", "?")} for p in data),
            key=lambda p: p["name"].lower(),
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired,
            FileNotFoundError, json.JSONDecodeError):
        return []


def pip_install(package: str) -> tuple[bool, str]:
    return _pip(["install", package])


def pip_uninstall(package: str) -> tuple[bool, str]:
    return _pip(["uninstall", "-y", package])


def _pip(args: list[str]) -> tuple[bool, str]:
    exe = python_executable()
    cmd = [exe, "-m", "pip", *args, "--disable-pip-version-check"]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return False, f"{type(e).__name__}: {e}"
    log = (out.stdout or "") + (out.stderr or "")
    if out.returncode == 0:
        return True, log.strip()[-4000:]
    if "externally-managed" in log or "break-system-packages" in log:
        try:
            out2 = subprocess.run(cmd + ["--break-system-packages"],
                                  capture_output=True, text=True, timeout=600)
            log2 = (out2.stdout or "") + (out2.stderr or "")
            return out2.returncode == 0, log2.strip()[-4000:]
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            return False, f"{type(e).__name__}: {e}"
    return False, log.strip()[-4000:]


def ollama_installed() -> bool:
    return ollama_binary() is not None


def ollama_running() -> bool:
    return ollama_models(_raw=True) is not None


def ollama_models(_raw: bool = False):
    try:
        with urllib.request.urlopen(f"{OLLAMA_API}/api/tags", timeout=3) as res:
            data = json.loads(res.read().decode("utf-8", "replace"))
        models = data.get("models", []) or []
        return models if not _raw else models
    except (urllib.error.URLError, OSError, ValueError, TimeoutError):
        return None if _raw else []


def ollama_pull(model: str):
    if not model.strip():
        yield ("error", "No model name given.")
        return
    try:
        proc = subprocess.Popen(
            ["ollama", "pull", model.strip()],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1,
        )
    except (OSError, FileNotFoundError) as e:
        yield ("error", f"Ollama not executable: {e}")
        return
    for line in iter(proc.stdout.readline, ""):
        if line:
            yield ("line", line.rstrip())
    proc.wait()
    yield ("done", proc.returncode == 0)


def ollama_remove(model: str) -> tuple[bool, str]:
    if not model.strip():
        return False, "No model name given."
    try:
        out = subprocess.run(["ollama", "rm", model.strip()],
                             capture_output=True, text=True, timeout=60)
    except (OSError, FileNotFoundError, subprocess.TimeoutExpired) as e:
        return False, f"{type(e).__name__}: {e}"
    log = (out.stdout or "") + (out.stderr or "")
    return out.returncode == 0, log.strip()



EXPORT_EXCLUDE_DIRS = {
    "__pycache__", ".git", "nexusvenv", "venv", ".venv", ".idea", ".vscode",
    "node_modules", ".claude", ".mypy_cache", ".pytest_cache", "outbox_spool",
    ".ollama",
}
EXPORT_EXCLUDE_EXT = {
    ".pyc", ".pyo", ".so", ".dylib", ".dll", ".o", ".sqlite3", ".db",
    ".log", ".tmp", ".swp",
}
EXPORT_EXCLUDE_NAMES = {".DS_Store", "nexus_config.json"}


def export_project_zip(dest_path: str, progress=None) -> int:
    import zipfile

    dest_abs = os.path.abspath(dest_path)
    root = str(PROJECT_ROOT)
    count = 0
    with zipfile.ZipFile(dest_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in EXPORT_EXCLUDE_DIRS]
            for name in filenames:
                full = os.path.join(dirpath, name)
                if os.path.abspath(full) == dest_abs:
                    continue
                if name in EXPORT_EXCLUDE_NAMES:
                    continue
                if os.path.splitext(name)[1].lower() in EXPORT_EXCLUDE_EXT:
                    continue
                if os.path.islink(full) or not os.path.isfile(full):
                    continue
                try:
                    arcname = os.path.join("Nexusscan_full", os.path.relpath(full, root))
                    zf.write(full, arcname)
                    count += 1
                    if progress and count % 100 == 0:
                        progress(count)
                except OSError:
                    continue
    return count


def _privilege_prefix():
    try:
        if os.geteuid() == 0:
            return []
    except AttributeError:
        pass
    for tool in ("sudo", "doas"):
        if shutil.which(tool):
            return [tool]
    return None


def _ollama_unit_exists() -> bool:
    if not shutil.which("systemctl"):
        return False
    try:
        r = subprocess.run(["systemctl", "cat", "ollama"],
                           capture_output=True, text=True, timeout=10)
        return r.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _ollama_serve_pids() -> list[int]:
    pids = []
    try:
        entries = os.listdir("/proc")
    except OSError:
        return pids
    for entry in entries:
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/cmdline", "rb") as f:
                parts = [p.decode("utf-8", "replace") for p in f.read().split(b"\x00") if p]
        except OSError:
            continue
        if len(parts) >= 2 and parts[0].rsplit("/", 1)[-1] == "ollama" and "serve" in parts[1:]:
            pids.append(int(entry))
    return pids


def ollama_server_running() -> bool:
    return ollama_models(_raw=True) is not None


def stop_ollama() -> tuple[bool, str]:
    import signal
    import time

    if _ollama_unit_exists():
        priv = _privilege_prefix()
        if priv is None:
            return False, "Root privileges needed. Manually: sudo systemctl stop ollama"
        try:
            r = subprocess.run(priv + ["systemctl", "stop", "ollama"],
                               capture_output=True, text=True, timeout=30)
        except (OSError, subprocess.TimeoutExpired) as e:
            return False, f"{type(e).__name__}: {e}"
        if r.returncode == 0:
            return True, "Ollama service stopped."
        return False, (r.stderr or r.stdout or "systemctl stop fehlgeschlagen").strip()

    pids = _ollama_serve_pids()
    if not pids:
        return True, "Ollama is not running."
    stopped, errors = [], []
    for pid in pids:
        try:
            os.kill(pid, signal.SIGTERM)
            stopped.append(pid)
        except PermissionError:
            errors.append(f"PID {pid}: permission denied")
        except ProcessLookupError:
            pass
    time.sleep(1)
    for pid in stopped:
        try:
            os.kill(pid, 0)
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
    if errors:
        return False, " · ".join(errors) + " (try running as root)"
    return True, f"Ollama process terminated (PID {', '.join(map(str, stopped))})."


def start_ollama() -> tuple[bool, str]:
    import time

    if ollama_server_running():
        return True, "Ollama is already running."

    if _ollama_unit_exists():
        priv = _privilege_prefix()
        if priv is None:
            return False, "Root privileges needed. Manually: sudo systemctl start ollama"
        try:
            r = subprocess.run(priv + ["systemctl", "start", "ollama"],
                               capture_output=True, text=True, timeout=30)
        except (OSError, subprocess.TimeoutExpired) as e:
            return False, f"{type(e).__name__}: {e}"
        if r.returncode != 0:
            return False, (r.stderr or r.stdout or "systemctl start fehlgeschlagen").strip()
    else:
        try:
            subprocess.Popen(["ollama", "serve"], stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, start_new_session=True)
        except (OSError, FileNotFoundError) as e:
            return False, f"'ollama serve' fehlgeschlagen: {e}"

    for _ in range(15):
        if ollama_server_running():
            return True, "Ollama started."
        time.sleep(1)
    return False, "Ollama did not respond after starting."


SUGGESTED_MODELS = [
    ("llama3.2:3b", "~2 GB", "fast, CPU-friendly"),
    ("llama3.1:8b", "~4.7 GB", "recommended - best quality per GB"),
    ("qwen2.5:14b", "~9 GB", "strongest analysis, GPU recommended"),
    ("mistral:7b", "~4.1 GB", "solid all-purpose alternative"),
]
