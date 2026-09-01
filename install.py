import json
import os
import shutil
import subprocess
import time
import sys
import platform
import urllib.error
import urllib.request

installer_ascii = r"""
 __   _ _______ _     _ _     _ _______ _______ _______ _______ __   _      _____ __   _ _______ _______ _______               _______  ______
 | \  | |______  \___/  |     | |______ |______ |       |_____| | \  |        |   | \  | |______    |    |_____| |      |      |______ |_____/
 |  \_| |______ _/   \_ |_____| ______| ______| |_____  |     | |  \_|      __|__ |  \_| ______|    |    |     | |_____ |_____ |______ |    \_
"""

REQUIRED_PACKAGES = [
    "colorama",
    "scapy",
    "tqdm",
    "pycryptodome",
    "distro",
    "sherlock-project",
    "PyQt5"
]

PKG_MANAGERS = [
    {"id": "pacman", "binary": "pacman",
     "install": ["pacman", "-S", "--noconfirm", "--needed"],
     "refresh": ["pacman", "-Sy", "--noconfirm"], "label": "pacman (Arch)"},
    {"id": "apt", "binary": "apt-get",
     "install": ["apt-get", "install", "-y"],
     "refresh": ["apt-get", "update"], "label": "apt (Debian/Ubuntu)"},
    {"id": "dnf", "binary": "dnf",
     "install": ["dnf", "install", "-y"],
     "refresh": None, "label": "dnf (Fedora/RHEL)"},
    {"id": "yum", "binary": "yum",
     "install": ["yum", "install", "-y"],
     "refresh": None, "label": "yum (CentOS/RHEL)"},
    {"id": "zypper", "binary": "zypper",
     "install": ["zypper", "--non-interactive", "install"],
     "refresh": ["zypper", "--non-interactive", "refresh"], "label": "zypper (openSUSE)"},
    {"id": "apk", "binary": "apk",
     "install": ["apk", "add"],
     "refresh": ["apk", "update"], "label": "apk (Alpine)"},
    {"id": "xbps", "binary": "xbps-install",
     "install": ["xbps-install", "-y"],
     "refresh": ["xbps-install", "-S"], "label": "xbps (Void)"},
    {"id": "emerge", "binary": "emerge",
     "install": ["emerge", "--noreplace"],
     "refresh": None, "label": "portage (Gentoo)"},
    {"id": "eopkg", "binary": "eopkg",
     "install": ["eopkg", "install", "-y"],
     "refresh": None, "label": "eopkg (Solus)"},
    {"id": "swupd", "binary": "swupd",
     "install": ["swupd", "bundle-add"],
     "refresh": None, "label": "swupd (Clear Linux)"},
    {"id": "nix", "binary": "nix-env",
     "install": ["nix-env", "-iA"],
     "refresh": None, "label": "nix (NixOS)"},
    {"id": "pkcon", "binary": "pkcon",
     "install": ["pkcon", "-y", "install"],
     "refresh": None, "label": "PackageKit (generisch)"},
]

SYSTEM_TOOLS = {
    "nmap": {
        "binary": "nmap",
        "why": "port scans (menu 1)",
        "default": "nmap",
        "emerge": "net-analyzer/nmap",
        "nix": "nixpkgs.nmap",
        "swupd": "network-basic",
    },
    "wireless-tools": {
        "binary": "iwconfig",
        "why": "detect Wi-Fi interfaces",
        "default": "wireless-tools",
        "pacman": "wireless_tools",
        "zypper": "wireless_tools",
        "xbps": "wireless_tools",
        "emerge": "net-wireless/wireless-tools",
        "nix": "nixpkgs.wirelesstools",
        "swupd": "network-basic",
    },
    "net-tools": {
        "binary": "ifconfig",
        "why": "classic network commands",
        "default": "net-tools",
        "emerge": "sys-apps/net-tools",
        "nix": "nixpkgs.nettools",
        "swupd": "network-basic",
    },
    "curl": {
        "binary": "curl",
        "why": "downloads (incl. Ollama setup)",
        "default": "curl",
        "emerge": "net-misc/curl",
        "nix": "nixpkgs.curl",
        "swupd": "network-basic",
    },
}

CORE_TOOLS = ["nmap", "wireless-tools", "net-tools"]

OLLAMA_API = "http://127.0.0.1:11434"
OLLAMA_INSTALL_SCRIPT = "https://ollama.com/install.sh"

OLLAMA_PACKAGES = {
    "pacman": "ollama",
    "zypper": "ollama",
    "apk": "ollama",
    "nix": "nixpkgs.ollama",
    "xbps": "ollama",
}

OLLAMA_MODELS = [
    ("llama3.2:3b", "~2 GB", "fast, usable on CPU without a GPU"),
    ("llama3.1:8b", "~4.7 GB", "recommended - best analysis quality per gigabyte"),
    ("qwen2.5:14b", "~9 GB", "strongest analysis, 12 GB+ VRAM GPU recommended"),
]
DEFAULT_OLLAMA_MODEL = "llama3.1:8b"

SUBPROJECT_REQUIREMENTS = [
    os.path.join("osint_dashboard", "requirements.txt"),
]


def read_subproject_requirements():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    packages = []
    for rel_path in SUBPROJECT_REQUIREMENTS:
        full_path = os.path.join(base_dir, rel_path)
        if not os.path.isfile(full_path):
            continue
        subproject = os.path.dirname(rel_path) or rel_path
        with open(full_path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                packages.append((line, subproject))
    return packages


def get_distro_id():
    os_release_paths = ["/etc/os-release", "/usr/lib/os-release"]
    for path in os_release_paths:
        if os.path.isfile(path):
            try:
                data = {}
                with open(path) as f:
                    for line in f:
                        line = line.strip()
                        if not line or "=" not in line:
                            continue
                        key, _, value = line.partition("=")
                        data[key] = value.strip('"').strip("'")
                name = data.get("PRETTY_NAME") or data.get("NAME") or ""
                distro_id = data.get("ID", "").lower()
                if distro_id:
                    return f"{name} ({distro_id})" if name else distro_id
                id_like = data.get("ID_LIKE", "").lower()
                if id_like:
                    return id_like.split()[0]
            except Exception:
                pass

    try:
        result = subprocess.run(
            ["lsb_release", "-is"], check=True, capture_output=True, text=True
        )
        return result.stdout.strip().lower()
    except Exception:
        pass

    return "unbekannt"


def privilege_prefix():
    try:
        if os.geteuid() == 0:
            return []
    except AttributeError:
        pass
    for tool in ("sudo", "doas"):
        if shutil.which(tool):
            return [tool]
    return None


def detect_pkg_manager():
    for pm in PKG_MANAGERS:
        if shutil.which(pm["binary"]):
            return pm
    return None


def pkg_manager_refresh(pm, priv):
    if not pm or not pm.get("refresh") or priv is None:
        return
    try:
        subprocess.run(priv + pm["refresh"], check=True, capture_output=True, text=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass


def package_name_for(tool_name, pm_id):
    cfg = SYSTEM_TOOLS[tool_name]
    return cfg.get(pm_id, cfg.get("default"))


def install_system_package(tool_name, pm, priv, quiet=False):
    cfg = SYSTEM_TOOLS[tool_name]
    binary = cfg["binary"]

    if shutil.which(binary):
        if not quiet:
            print(f"  → {tool_name} is already installed ✓")
        return True

    if pm is None:
        print(f"  ✗ {tool_name} is missing and no package manager was found.")
        print(f"    Please install it manually (provides '{binary}').")
        return False

    pkg = package_name_for(tool_name, pm["id"])
    if not pkg:
        print(f"  ✗ No package name is set for {tool_name} on {pm['label']}.")
        print(f"    Please install it manually (provides '{binary}').")
        return False

    if priv is None:
        print(f"  ✗ {tool_name} needs root, but neither sudo nor doas is available.")
        print(f"    Run as root: {' '.join(pm['install'])} {pkg}")
        return False

    print(f"  → Installing {tool_name} ({pkg} via {pm['label']})...", end=" ", flush=True)
    try:
        subprocess.run(priv + pm["install"] + [pkg], check=True,
                       capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        print("✗")
        detail = (e.stderr or e.stdout or "").strip().splitlines()
        if detail:
            print(f"    {detail[-1][:200]}")
        print(f"    Manually: {' '.join(pm['install'])} {pkg}")
        return False
    except FileNotFoundError:
        print("✗ package manager not executable")
        return False

    if shutil.which(binary):
        print("✓")
        return True
    for extra in ("/sbin", "/usr/sbin", "/usr/local/sbin"):
        if os.path.exists(os.path.join(extra, binary)):
            print("✓")
            return True
    print("✗ (package installed, binary not found)")
    return False


def install_system_tools(pm, priv):
    results = {}
    pkg_manager_refresh(pm, priv)
    for tool_name in CORE_TOOLS:
        results[tool_name] = install_system_package(tool_name, pm, priv)
    return results


def detect_init_system():
    if shutil.which("systemctl") and os.path.isdir("/run/systemd/system"):
        return "systemd"
    if shutil.which("rc-service") or shutil.which("rc-update"):
        return "openrc"
    if shutil.which("sv") and os.path.isdir("/var/service"):
        return "runit"
    if shutil.which("s6-rc"):
        return "s6"
    if shutil.which("systemctl"):
        return "systemd"
    return "unbekannt"


def enable_service(name, priv):
    if priv is None:
        return False
    init = detect_init_system()
    try:
        if init == "systemd":
            subprocess.run(priv + ["systemctl", "enable", "--now", name],
                           check=True, capture_output=True, text=True)
            return True
        if init == "openrc":
            subprocess.run(priv + ["rc-update", "add", name, "default"],
                           check=False, capture_output=True, text=True)
            subprocess.run(priv + ["rc-service", name, "start"],
                           check=True, capture_output=True, text=True)
            return True
        if init == "runit":
            subprocess.run(priv + ["ln", "-sf", f"/etc/sv/{name}", "/var/service/"],
                           check=True, capture_output=True, text=True)
            return True
        if init == "s6":
            subprocess.run(priv + ["s6-rc", "-u", "change", name],
                           check=True, capture_output=True, text=True)
            return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False
    return False


def ensure_pip():
    try:
        subprocess.run(
            [sys.executable, "-m", "pip", "--version"],
            check=True, capture_output=True, text=True
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("[!] pip is not available. Trying to install it via ensurepip...")
        try:
            subprocess.run([sys.executable, "-m", "ensurepip", "--upgrade"], check=True)
            return True
        except Exception:
            pass

        pm, priv = detect_pkg_manager(), privilege_prefix()
        if pm and priv is not None:
            pkg = {"apt": "python3-pip", "pacman": "python-pip", "dnf": "python3-pip",
                   "yum": "python3-pip", "zypper": "python3-pip", "apk": "py3-pip",
                   "xbps": "python3-pip", "emerge": "dev-python/pip",
                   "eopkg": "python3-pip"}.get(pm["id"])
            if pkg:
                print(f"  → Trying to install pip via {pm['label']}...")
                try:
                    subprocess.run(priv + pm["install"] + [pkg], check=True)
                    return True
                except subprocess.CalledProcessError:
                    pass

        print("[!] Could not install pip.")
        print("    Please install it manually, e.g.: sudo apt install python3-pip")
        return False


def install_pip_packages(python_executable=None):
    if python_executable is None:
        python_executable = sys.executable

    subproject_pkgs = read_subproject_requirements()
    all_packages = list(REQUIRED_PACKAGES)
    for pkg, _src in subproject_pkgs:
        if pkg not in all_packages:
            all_packages.append(pkg)

    if subproject_pkgs:
        print(f"  → found {len(subproject_pkgs)} extra packages from sub-projects "
              f"({', '.join(pkg for pkg, _src in subproject_pkgs)})")

    print(f"\n[+] Installing Python packages with {python_executable}...\n")
    for pkg in all_packages:
        print(f"  → Installing {pkg}...", end=" ", flush=True)
        try:
            subprocess.run(
                [python_executable, "-m", "pip", "install", pkg],
                check=True, capture_output=True, text=True
            )
            print("✓")
        except subprocess.CalledProcessError as e:
            print(f"✗ ERROR: {e.stderr.strip()}")
            print(f"    Trying with --break-system-packages...")
            try:
                subprocess.run(
                    [python_executable, "-m", "pip", "install", pkg, "--break-system-packages"],
                    check=True, capture_output=True, text=True
                )
                print("  ✓")
            except subprocess.CalledProcessError as e2:
                print(f"    ✗ Could not install {pkg}: {e2.stderr.strip()}")
                return False
    print(f"\n[✓] All {len(all_packages)} packages installed!")
    return True


def ollama_api_models():
    try:
        with urllib.request.urlopen(f"{OLLAMA_API}/api/tags", timeout=3) as res:
            data = json.loads(res.read().decode("utf-8", "replace"))
        return [m.get("name", "") for m in data.get("models", []) if m.get("name")]
    except (urllib.error.URLError, OSError, ValueError, TimeoutError):
        return None


def ollama_arch_supported():
    return platform.machine().lower() in ("x86_64", "amd64", "aarch64", "arm64")


def install_ollama_via_script(pm, priv):
    if not ollama_arch_supported():
        print(f"  ✗ There is no prebuilt Ollama binary for the CPU architecture")
        print("    '{platform.machine()}'. Build it manually: https://github.com/ollama/ollama")
        return False

    print(f"\n  There is no Ollama distro package for this system.")
    print(f"  Official install: curl -fsSL {OLLAMA_INSTALL_SCRIPT} | sh")
    print("  The script downloads the Ollama binary and, where possible, sets up a service.")
    answer = input("  Run this script now? (y/n): ").strip().lower()
    if answer not in ["y", "j", "yes", "ja"]:
        print("  ℹ Skipped. Until then the dashboard uses its offline analyzer.")
        return False

    downloader = None
    if shutil.which("curl"):
        downloader = f"curl -fsSL {OLLAMA_INSTALL_SCRIPT}"
    elif shutil.which("wget"):
        downloader = f"wget -qO- {OLLAMA_INSTALL_SCRIPT}"
    else:
        print("  → Neither curl nor wget present - installing curl...")
        if install_system_package("curl", pm, priv, quiet=True) and shutil.which("curl"):
            downloader = f"curl -fsSL {OLLAMA_INSTALL_SCRIPT}"
        else:
            print("  ✗ No downloader available - Ollama cannot be fetched.")
            return False

    try:
        subprocess.run(f"{downloader} | sh", shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"  ✗ Installation failed: {e}")
        return False

    if not shutil.which("ollama") and not os.path.exists("/usr/local/bin/ollama"):
        print("  ✗ Ollama binary not found after installation.")
        return False
    print("  ✓ Ollama installed")
    return True


def install_ollama_binary(pm, priv):
    if shutil.which("ollama"):
        print("  → Ollama is already installed ✓")
        return True

    pkg = OLLAMA_PACKAGES.get(pm["id"]) if pm else None
    if pkg and priv is not None:
        print(f"  → Installing Ollama ({pkg} via {pm['label']})...", flush=True)
        try:
            subprocess.run(priv + pm["install"] + [pkg], check=True)
            if shutil.which("ollama"):
                print("  ✓ Ollama installed")
                return True
            print("  ! Package installed, but no 'ollama' binary in PATH.")
        except subprocess.CalledProcessError as e:
            print(f"  ! Package install failed ({e}) - trying the official script...")
        except FileNotFoundError:
            pass

    return install_ollama_via_script(pm, priv)


def start_ollama_service(priv):
    if ollama_api_models() is not None:
        print("  → Ollama server is already running ✓")
        return True

    init = detect_init_system()
    if init != "unbekannt":
        print(f"  → Enabling and starting the ollama service ({init})...", flush=True)
        enable_service("ollama", priv)

        for _ in range(20):
            if ollama_api_models() is not None:
                print(f"  ✓ Ollama server reachable at {OLLAMA_API}")
                return True
            time.sleep(1)

    print("  → No running service - starting 'ollama serve' in the background...")
    try:
        subprocess.Popen(
            ["ollama", "serve"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except (OSError, FileNotFoundError) as e:
        print(f"  ✗ 'ollama serve' could not be started: {e}")
        return False

    for _ in range(15):
        if ollama_api_models() is not None:
            print("  ✓ Ollama server running (background process, ends on reboot -")
            if init == "systemd":
                print("    dauerhaft: sudo systemctl enable --now ollama)")
            elif init == "openrc":
                print("    dauerhaft: sudo rc-update add ollama default)")
            else:
                print("    to persist: add 'ollama serve' to your startup)")
            return True
        time.sleep(1)

    print(f"  ✗ Ollama server does not respond on {OLLAMA_API}")
    return False


def choose_ollama_model(installed):
    print("\n  Which local model should be pulled for the AI analysis?")
    for i, (name, size, note) in enumerate(OLLAMA_MODELS, start=1):
        marker = "  [already present]" if any(
            m.startswith(name.split(":")[0]) for m in installed) else ""
        default = "  (default)" if name == DEFAULT_OLLAMA_MODEL else ""
        print(f"    {i}) {name:<14} {size:<9} - {note}{default}{marker}")
    print(f"    {len(OLLAMA_MODELS) + 1}) pull no model (dashboard uses the offline analyzer)")

    choice = input(f"  Choice [1-{len(OLLAMA_MODELS) + 1}, Enter = default]: ").strip()
    if not choice:
        return DEFAULT_OLLAMA_MODEL
    if not choice.isdigit() or not 1 <= int(choice) <= len(OLLAMA_MODELS) + 1:
        print("  ! Invalid choice - skipping the model download.")
        return None
    idx = int(choice)
    return None if idx == len(OLLAMA_MODELS) + 1 else OLLAMA_MODELS[idx - 1][0]


def pull_ollama_model(model):
    print(f"\n  → Downloading model '{model}' (this can take a few minutes)...\n")
    try:
        subprocess.run(["ollama", "pull", model], check=True)
        print(f"\n  ✓ Model '{model}' ready")
        return True
    except subprocess.CalledProcessError as e:
        print(f"\n  ✗ Download failed: {e}")
        print(f"    Do it later with: ollama pull {model}")
        return False
    except FileNotFoundError:
        print("  ✗ 'ollama' not found in PATH.")
        return False


def setup_local_ai(pm, priv):
    print("\n[+] Local AI for the OSINT dashboard (AI OSINT analyst)")
    print("    Runs fully offline on this machine - no API key, no cloud.")
    print("    Without a local model the dashboard automatically uses its")
    print("    built-in offline analyzer (entity extraction + correlation).")

    answer = input("\n  Install Ollama + a local model now? (y/n): ").strip().lower()
    if answer not in ["y", "j", "yes", "ja"]:
        print("  ℹ Skipped - the offline analyzer still works.")
        return ("Local AI skipped (offline analyzer active)", True)

    if not install_ollama_binary(pm, priv):
        return ("Ollama not installed (offline analyzer active)", False)

    if not start_ollama_service(priv):
        return ("Ollama installed, server won't start (offline analyzer active)", False)

    installed = ollama_api_models() or []
    if installed:
        print(f"  → Already present models: {', '.join(installed)}")

    model = choose_ollama_model(installed)
    if model is None:
        if installed:
            return (f"Ollama running with existing models ({len(installed)})", True)
        return ("Ollama running, no model pulled (offline analyzer active)", True)

    if not pull_ollama_model(model):
        return (f"Ollama running, model '{model}' missing (offline analyzer active)", False)

    return (f"Local AI ready - Ollama with '{model}'", True)


def create_requirements_file():
    req_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "requirements.txt")
    try:
        with open(req_path, "w") as f:
            for pkg in REQUIRED_PACKAGES:
                f.write(f"{pkg}\n")
        print(f"  → requirements.txt written to: {req_path}")
        return True
    except Exception as e:
        print(f"  ! requirements.txt could not be written: {e}")
        return False


def create_venv(venv_name, pm, priv):
    try:
        subprocess.run([sys.executable, "-m", "venv", venv_name],
                       check=True, capture_output=True, text=True)
        return True
    except subprocess.CalledProcessError as e:
        stderr = (e.stderr or "") + (e.stdout or "")
        print(f"  ! venv creation failed: {stderr.strip().splitlines()[-1][:200]}"
              if stderr.strip() else "  ! venv creation failed")

        venv_pkg = {"apt": "python3-venv", "dnf": "python3-virtualenv",
                    "yum": "python3-virtualenv", "zypper": "python3-virtualenv",
                    "apk": "py3-virtualenv"}.get(pm["id"]) if pm else None
        if not venv_pkg or priv is None:
            return False

        print(f"  → Installing {venv_pkg} and trying again...")
        try:
            subprocess.run(priv + pm["install"] + [venv_pkg], check=True,
                           capture_output=True, text=True)
            subprocess.run([sys.executable, "-m", "venv", venv_name], check=True)
            return True
        except subprocess.CalledProcessError:
            return False


def run_installer(pm, priv):
    a = input("Use a virtual environment? (y/n): ").strip().lower()
    venv_name = "nexusvenv"

    if a in ["y", "j", "yes", "ja"]:
        print("\n[+] Using a virtual environment...")
        time.sleep(0.3)
        try:
            print(f"  → Creating venv '{venv_name}'...")
            if not create_venv(venv_name, pm, priv):
                print("\n[!] Could not create the virtual environment.")
                print("    Run the installer again and choose 'n' (global install).")
                sys.exit(1)
            print(f"  ✓ Virtual environment '{venv_name}' created")

            python_executable = os.path.join(venv_name, "bin", "python")

            print("  → Upgrading pip...")
            subprocess.run([python_executable, "-m", "pip", "install", "--upgrade", "pip"],
                            check=True, capture_output=True)

            if not install_pip_packages(python_executable):
                print("\n[!] Installation error. Try manually with:")
                print(f"    source {venv_name}/bin/activate && pip install -r requirements.txt")
                sys.exit(1)

            tool_results = install_system_tools(pm, priv)
            ai_status, ai_ok = setup_local_ai(pm, priv)
            create_requirements_file()

            print(f"\n{'=' * 50}")
            print(f"  ✓ Installation completed successfully!")
            print(f"  ✓ Python packages (incl. osint_dashboard) installed")
            for tool_name, ok in tool_results.items():
                status = "✓" if ok else "✗ (manuell nachinstallieren)"
                print(f"  {status} {tool_name}")
            print(f"  {'✓' if ai_ok else 'ℹ'} {ai_status}")
            print(f"  ℹ sqlmap is used as an external system tool")
            print(f"  ℹ Airbreak (menu 7) installs the aircrack-ng suite/mdk4/gnome-terminal itself")
            print(f"\n  Start NexusScan with:")
            print(f"    source {venv_name}/bin/activate")
            print(f"    sudo {python_executable} Nexusscan.py")
            print(f"{'=' * 50}")
        except subprocess.CalledProcessError as e:
            print(f"\n[!] Installation error: {e}")
            sys.exit(1)

    elif a in ["n", "no", "nein"]:
        print("\n[+] Global install (no venv)...")
        time.sleep(0.3)
        print("  → Installing packages system-wide...")
        if not install_pip_packages():
            print("\n  ! Trying with --break-system-packages...")
            for pkg in REQUIRED_PACKAGES:
                try:
                    subprocess.run(
                        [sys.executable, "-m", "pip", "install", pkg, "--break-system-packages"],
                        check=True, capture_output=True
                    )
                except Exception:
                    pass

        tool_results = install_system_tools(pm, priv)
        ai_status, ai_ok = setup_local_ai(pm, priv)
        create_requirements_file()

        print(f"\n{'=' * 50}")
        print(f"  ✓ Global install complete!")
        for tool_name, ok in tool_results.items():
            status = "✓" if ok else "✗ (manuell nachinstallieren)"
            print(f"  {status} {tool_name}")
        print(f"  {'✓' if ai_ok else 'ℹ'} {ai_status}")
        print(f"  ℹ sqlmap is used as an external system tool")
        print(f"  ℹ Airbreak (menu 7) installs the aircrack-ng suite/mdk4/gnome-terminal itself")
        print(f"  ✓ Start NexusScan with: sudo python3 Nexusscan.py")
        print(f"{'=' * 50}")
    else:
        print("Invalid input. Aborting.")
        sys.exit(1)


def os_detection():
    current_os = platform.system()

    if current_os == "Windows":
        print("\n" + "!" * 60)
        print("  NEXUSSCAN IS LINUX ONLY")
        print("!" * 60)
        print("\n  Nexusscan.py nutzt folgende Linux-spezifische Features:")
        print("    • airmon-ng / airodump-ng / aircrack-ng")
        print("    • Scapy raw socket access")
        print("    • gnome-terminal for parallel processes")
        print("    • Linux tool execution via subprocess")
        print("\n  This installation will now stop.")
        print("  Please use NexusScan on Kali Linux, Parrot OS, Ubuntu or similar.")
        print("\n  Alternatively install manually:")
        print(f"    pip install {' '.join(REQUIRED_PACKAGES)}")
        print("\n" + "!" * 60)
        sys.exit(1)

    if current_os != "Linux":
        print(f"\n[!] Only Linux is supported. Detected: {current_os}")
        print(f"    Manual install: pip install {' '.join(REQUIRED_PACKAGES)}")
        sys.exit(1)

    try:
        distro = get_distro_id()
        pm = detect_pkg_manager()
        priv = privilege_prefix()
        init = detect_init_system()

        print(f"\n[+] Detected system  : {distro}")
        print(f"[+] Package manager  : {pm['label'] if pm else 'none found'}")
        print(f"[+] Init system      : {init}")
        if priv is None:
            print("[+] Root access      : none (no root, sudo or doas)")
        elif priv:
            print(f"[+] Root access      : via {priv[0]}")
        else:
            print("[+] Root access      : running as root")

        if pm is None:
            print("\n[!] No known package manager found.")
            print("    Python packages are installed anyway; system tools")
            print("    (nmap, wireless-tools, net-tools) you must add yourself.")
        if priv is None:
            print("\n[!] Without root/sudo/doas no system packages can be installed.")
            print("    Python packages and the offline analyzer still work.")

        run_installer(pm, priv)

    except KeyboardInterrupt:
        print("\n\n[!] Cancelled by the user.")
        sys.exit(0)
    except PermissionError:
        print("\n[!] Insufficient privileges. Please run with sudo.")
        print("    sudo python3 install.py")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Unexpected error: {e}")
        sys.exit(1)


def main():
    print("=" * 60)
    print(installer_ascii)
    print("=" * 60)
    print("  NEXUSSCAN - Installer v2.3")
    print("  Installs all required dependencies")
    print("  Linux - distro-independent (apt, pacman, dnf, zypper, apk, xbps, ...)")
    print("=" * 60)

    if not ensure_pip():
        sys.exit(1)

    subproject_pkgs = read_subproject_requirements()

    print(f"\n  The following Python packages will be installed:")
    for pkg in REQUIRED_PACKAGES:
        print(f"    • {pkg}")
    for pkg, src in subproject_pkgs:
        print(f"    • {pkg}  ({src})")

    print(f"\n  The following system packages will be installed:")
    for tool_name in CORE_TOOLS:
        print(f"    • {tool_name}  ({SYSTEM_TOOLS[tool_name]['why']})")
    print(f"\n  Optional (you'll be asked):")
    print(f"    • Ollama + a local AI model for the dashboard's AI OSINT analyst")
    print(f"      (runs offline on this machine, no API key; model from ~2 GB)")
    print(f"\n  ℹ sqlmap must be installed separately and available in PATH")
    print(f"  ℹ aircrack-ng, airmon-ng, airodump-ng, aireplay-ng, mdk4 and gnome-terminal")
    print(f"    are installed by Airbreak (menu item 7) on first start")
    print()
    os_detection()


if __name__ == "__main__":
    main()
