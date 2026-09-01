from __future__ import annotations

import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))


def launch():
    try:
        from PyQt5.QtWidgets import QApplication
    except Exception as exc:
        print(f"[!] PyQt5 is not available: {exc}")
        print("    Install with: pip install PyQt5")
        return

    from nexus_settings.settings_window import SettingsWindow

    app = QApplication.instance()
    owns_app = app is None
    if owns_app:
        app = QApplication(sys.argv)

    window = SettingsWindow()
    window.show()

    if owns_app:
        app.exec_()
    else:
        launch._window_ref = window


if __name__ == "__main__":
    launch()
