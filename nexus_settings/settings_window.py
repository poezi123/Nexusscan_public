from __future__ import annotations

import os

from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtWidgets import (
    QWidget, QTabWidget, QVBoxLayout, QHBoxLayout, QFormLayout, QLabel,
    QPushButton, QLineEdit, QSpinBox, QComboBox, QCheckBox, QListWidget,
    QListWidgetItem, QPlainTextEdit, QGroupBox, QMessageBox, QInputDialog,
    QProgressBar, QAbstractItemView, QFileDialog,
)

from nexus_settings import config as cfg
from nexus_settings import sysinfo as si


class FuncWorker(QThread):
    finished_result = pyqtSignal(bool, str)

    def __init__(self, fn, *args):
        super().__init__()
        self._fn, self._args = fn, args

    def run(self):
        try:
            ok, log = self._fn(*self._args)
        except Exception as exc:
            ok, log = False, f"{type(exc).__name__}: {exc}"
        self.finished_result.emit(bool(ok), str(log))


class PullWorker(QThread):
    line = pyqtSignal(str)
    finished_result = pyqtSignal(bool, str)

    def __init__(self, model):
        super().__init__()
        self._model = model

    def run(self):
        ok = False
        try:
            for kind, payload in si.ollama_pull(self._model):
                if kind == "line":
                    self.line.emit(payload)
                elif kind == "error":
                    self.finished_result.emit(False, payload)
                    return
                elif kind == "done":
                    ok = bool(payload)
        except Exception as exc:
            self.finished_result.emit(False, f"{type(exc).__name__}: {exc}")
            return
        self.finished_result.emit(ok, self._model)


class SizeWorker(QThread):
    done = pyqtSignal(list)

    def run(self):
        try:
            self.done.emit(si.storage_breakdown())
        except Exception:
            self.done.emit([])


class SettingsWindow(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("NexusScan - Settings")
        self.resize(720, 560)
        self._settings = cfg.load()
        self._worker = None

        root = QVBoxLayout(self)
        header = QLabel("⚙  NexusScan Settings")
        header.setStyleSheet("font-size: 16px; font-weight: bold; padding: 4px;")
        root.addWidget(header)

        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_storage_tab(), "Storage")
        self.tabs.addTab(self._build_packages_tab(), "Python packages")
        if si.ollama_installed():
            self.tabs.addTab(self._build_ollama_tab(), "Ollama && AI")
        self.tabs.addTab(self._build_maintenance_tab(), "Maintenance")
        root.addWidget(self.tabs)

        self.status = QLabel("")
        self.status.setStyleSheet("color: gray; padding: 2px;")
        root.addWidget(self.status)

        self.refresh_storage()
        self.refresh_packages()

    def _busy(self) -> bool:
        if self._worker and self._worker.isRunning():
            QMessageBox.information(self, "Please wait",
                                    "Another action is still running. Please wait a moment.")
            return True
        return False

    def _set_status(self, text: str):
        self.status.setText(text)

    def _build_storage_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)

        info = QLabel(
            "Disk used by the project and all dependencies needed to "
            "run it (Python environment, Ollama program and models)."
        )
        info.setWordWrap(True)
        lay.addWidget(info)

        self.storage_list = QListWidget()
        self.storage_list.setSelectionMode(QAbstractItemView.NoSelection)
        lay.addWidget(self.storage_list)

        self.storage_total = QLabel("Total: calculating …")
        self.storage_total.setStyleSheet("font-weight: bold; padding: 4px;")
        lay.addWidget(self.storage_total)

        row = QHBoxLayout()
        self.storage_refresh_btn = QPushButton("Recalculate")
        self.storage_refresh_btn.clicked.connect(self.refresh_storage)
        row.addStretch()
        row.addWidget(self.storage_refresh_btn)
        lay.addLayout(row)
        return w

    def refresh_storage(self):
        self.storage_list.clear()
        self.storage_total.setText("Total: calculating …")
        self.storage_refresh_btn.setEnabled(False)
        self._size_worker = SizeWorker()
        self._size_worker.done.connect(self._on_storage_done)
        self._size_worker.start()

    def _on_storage_done(self, items: list):
        self.storage_list.clear()
        total = 0
        for it in items:
            total += it["bytes"]
            entry = QListWidgetItem(f"{it['label']:<34}{si.human_size(it['bytes']):>12}\n    {it['note']}")
            self.storage_list.addItem(entry)
        self.storage_total.setText(f"Total: {si.human_size(total)}")
        self.storage_refresh_btn.setEnabled(True)

    def _build_packages_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)

        lay.addWidget(QLabel(
            f"Packages in the Python environment (nexusvenv). Interpreter:\n{si.python_executable()}"
        ))

        if not si.venv_writable():
            warn = QLabel(
                "⚠ This environment is owned by another user (probably created with sudo). "
                "To install/uninstall, run NexusScan with the same "
                "privileges, e.g.: sudo python3 Nexusscan.py"
            )
            warn.setWordWrap(True)
            warn.setStyleSheet("color: #b00020;")
            lay.addWidget(warn)

        self.pkg_list = QListWidget()
        self.pkg_list.setSelectionMode(QAbstractItemView.SingleSelection)
        lay.addWidget(self.pkg_list)

        row = QHBoxLayout()
        self.pkg_input = QLineEdit()
        self.pkg_input.setPlaceholderText("Package name (e.g. requests or requests==2.32.0)")
        row.addWidget(self.pkg_input)
        install_btn = QPushButton("Install")
        install_btn.clicked.connect(self._on_pkg_install)
        row.addWidget(install_btn)
        uninstall_btn = QPushButton("Uninstall selected")
        uninstall_btn.clicked.connect(self._on_pkg_uninstall)
        row.addWidget(uninstall_btn)
        lay.addLayout(row)

        row2 = QHBoxLayout()
        refresh_btn = QPushButton("Refresh list")
        refresh_btn.clicked.connect(self.refresh_packages)
        row2.addStretch()
        row2.addWidget(refresh_btn)
        lay.addLayout(row2)

        self.pkg_log = QPlainTextEdit()
        self.pkg_log.setReadOnly(True)
        self.pkg_log.setMaximumHeight(140)
        self.pkg_log.setPlaceholderText("pip output …")
        lay.addWidget(self.pkg_log)
        return w

    def refresh_packages(self):
        self.pkg_list.clear()
        for p in si.pip_packages():
            self.pkg_list.addItem(f"{p['name']}=={p['version']}")
        self._set_status(f"{self.pkg_list.count()} packages in nexusvenv")

    def _on_pkg_install(self):
        if self._busy():
            return
        name = self.pkg_input.text().strip()
        if not name:
            QMessageBox.information(self, "No package", "Please enter a package name.")
            return
        self.pkg_log.appendPlainText(f"$ pip install {name}")
        self._run(si.pip_install, name, done=self._after_pkg)

    def _on_pkg_uninstall(self):
        if self._busy():
            return
        item = self.pkg_list.currentItem()
        if not item:
            QMessageBox.information(self, "Nothing selected",
                                    "Please select a package in the list.")
            return
        name = item.text().split("==")[0]
        if QMessageBox.question(
            self, "Uninstall?", f"Remove package '{name}' from nexusvenv?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        ) != QMessageBox.Yes:
            return
        self.pkg_log.appendPlainText(f"$ pip uninstall -y {name}")
        self._run(si.pip_uninstall, name, done=self._after_pkg)

    def _after_pkg(self, ok: bool, log: str):
        self.pkg_log.appendPlainText(log)
        self.pkg_log.appendPlainText("✓ done\n" if ok else "✗ failed\n")
        self.refresh_packages()

    def _build_ollama_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)

        models_box = QGroupBox("Installed Ollama models")
        mlay = QVBoxLayout(models_box)

        srv_row = QHBoxLayout()
        self.server_state_label = QLabel("")
        srv_row.addWidget(self.server_state_label, 1)
        self.server_toggle_btn = QPushButton("")
        self.server_toggle_btn.clicked.connect(self._on_server_toggle)
        srv_row.addWidget(self.server_toggle_btn)
        mlay.addLayout(srv_row)
        self._update_server_row()

        self.model_list = QListWidget()
        mlay.addWidget(self.model_list)

        rm_row = QHBoxLayout()
        rm_btn = QPushButton("Delete selected model")
        rm_btn.clicked.connect(self._on_model_remove)
        rm_row.addStretch()
        rm_row.addWidget(rm_btn)
        mlay.addLayout(rm_row)

        pull_row = QHBoxLayout()
        self.model_pick = QComboBox()
        self.model_pick.setEditable(True)
        for name, size, note in si.SUGGESTED_MODELS:
            self.model_pick.addItem(f"{name}  ({size} - {note})", name)
        pull_row.addWidget(self.model_pick, 1)
        self.pull_btn = QPushButton("Pull model")
        self.pull_btn.clicked.connect(self._on_model_pull)
        pull_row.addWidget(self.pull_btn)
        mlay.addLayout(pull_row)

        self.pull_progress = QProgressBar()
        self.pull_progress.setRange(0, 0)
        self.pull_progress.hide()
        mlay.addWidget(self.pull_progress)

        self.ollama_log = QPlainTextEdit()
        self.ollama_log.setReadOnly(True)
        self.ollama_log.setMaximumHeight(110)
        mlay.addWidget(self.ollama_log)
        lay.addWidget(models_box)

        ai_box = QGroupBox("AI settings (OSINT dashboard, local AI)")
        form = QFormLayout(ai_box)

        self.backend_combo = QComboBox()
        self.backend_combo.addItems(["auto", "ollama", "local_openai", "offline"])
        self.backend_combo.setCurrentText(str(self._settings["ai_backend"]))
        form.addRow("Backend:", self.backend_combo)

        self.model_combo = QComboBox()
        self.model_combo.setEditable(True)
        self.model_combo.addItem("")
        for m in si.ollama_models():
            self.model_combo.addItem(m.get("name", ""))
        self.model_combo.setCurrentText(str(self._settings["ollama_model"]))
        form.addRow("Ollama model (empty = auto):", self.model_combo)

        self.tokens_spin = QSpinBox()
        self.tokens_spin.setRange(128, 32768)
        self.tokens_spin.setSingleStep(128)
        self.tokens_spin.setValue(int(self._settings["max_tokens"]))
        self.tokens_spin.setToolTip("Cap on generated tokens. CPU models "
                                    "manage ~10 tokens/s - smaller = finishes faster.")
        form.addRow("Max tokens:", self.tokens_spin)

        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(30, 3600)
        self.timeout_spin.setSingleStep(30)
        self.timeout_spin.setValue(int(self._settings["timeout"]))
        self.timeout_spin.setSuffix(" s")
        form.addRow("Timeout:", self.timeout_spin)

        self.followup_combo = QComboBox()
        self.followup_combo.addItems(["auto", "always", "never"])
        self.followup_combo.setCurrentText(str(self._settings["followup_mode"]))
        self.followup_combo.setToolTip("Second round for the model's follow-up queries "
                                       "(SUCHE: …). auto = only when the first research was thin.")
        form.addRow("Follow-up round:", self.followup_combo)

        self.web_check = QCheckBox("Live research on by default")
        self.web_check.setChecked(bool(self._settings["web_default"]))
        self.web_check.setToolTip("Looks up detected entities in public "
                                  "sources. Search terms leave the machine when it does.")
        form.addRow(self.web_check)

        self.ollama_url_edit = QLineEdit(str(self._settings["ollama_url"]))
        form.addRow("Ollama URL:", self.ollama_url_edit)

        lay.addWidget(ai_box)

        save_row = QHBoxLayout()
        save_row.addStretch()
        save_btn = QPushButton("Save AI settings")
        save_btn.clicked.connect(self._on_save_ai)
        save_row.addWidget(save_btn)
        lay.addLayout(save_row)

        self.refresh_models()
        return w

    def refresh_models(self):
        self.model_list.clear()
        for m in si.ollama_models():
            self.model_list.addItem(f"{m.get('name', '?')}   {si.human_size(m.get('size', 0))}")

    def _update_server_row(self):
        running = si.ollama_server_running()
        state = "Server running" if running else "Server stopped"
        self.server_state_label.setText(f"Status: {state}  ·  {si.OLLAMA_API}")
        self.server_toggle_btn.setText("Stop Ollama" if running else "Start Ollama")

    def _on_server_toggle(self):
        if self._busy():
            return
        running = si.ollama_server_running()
        action = si.stop_ollama if running else si.start_ollama
        verb = "stopping" if running else "starting"
        self.ollama_log.appendPlainText(f"$ Ollama {verb} …")
        self.server_toggle_btn.setEnabled(False)
        self._run(action, done=self._after_server_toggle)

    def _after_server_toggle(self, ok: bool, msg: str):
        self.ollama_log.appendPlainText(("✓ " if ok else "✗ ") + (msg or ""))
        self.server_toggle_btn.setEnabled(True)
        self._update_server_row()
        self.refresh_models()

    def _on_model_remove(self):
        if self._busy():
            return
        item = self.model_list.currentItem()
        if not item:
            QMessageBox.information(self, "Nothing selected", "Please select a model.")
            return
        name = item.text().split()[0]
        if QMessageBox.question(
            self, "Delete model?", f"Delete Ollama model '{name}'?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        ) != QMessageBox.Yes:
            return
        self.ollama_log.appendPlainText(f"$ ollama rm {name}")
        self._run(si.ollama_remove, name, done=self._after_model_change)

    def _on_model_pull(self):
        if self._busy():
            return
        name = self.model_pick.currentData() or self.model_pick.currentText().split()[0]
        if not name:
            return
        self.ollama_log.appendPlainText(f"$ ollama pull {name}")
        self.pull_btn.setEnabled(False)
        self.pull_progress.show()
        self._worker = PullWorker(name)
        self._worker.line.connect(lambda ln: self.ollama_log.appendPlainText(ln))
        self._worker.finished_result.connect(self._after_pull)
        self._worker.start()

    def _after_pull(self, ok: bool, info: str):
        self.pull_progress.hide()
        self.pull_btn.setEnabled(True)
        self.ollama_log.appendPlainText("✓ model ready\n" if ok else f"✗ {info}\n")
        self._after_model_change(ok, "")

    def _after_model_change(self, ok: bool, log: str):
        if log:
            self.ollama_log.appendPlainText(log)
        self.refresh_models()
        if hasattr(self, "model_combo"):
            current = self.model_combo.currentText()
            self.model_combo.clear()
            self.model_combo.addItem("")
            for m in si.ollama_models():
                self.model_combo.addItem(m.get("name", ""))
            self.model_combo.setCurrentText(current)

    def _on_save_ai(self):
        self._settings.update({
            "ai_backend": self.backend_combo.currentText(),
            "ollama_model": self.model_combo.currentText().strip(),
            "max_tokens": self.tokens_spin.value(),
            "timeout": self.timeout_spin.value(),
            "followup_mode": self.followup_combo.currentText(),
            "web_default": self.web_check.isChecked(),
            "ollama_url": self.ollama_url_edit.text().strip() or cfg.DEFAULTS["ollama_url"],
        })
        try:
            cfg.save(self._settings)
        except OSError as e:
            QMessageBox.warning(self, "Save failed", str(e))
            return
        self._set_status("AI settings saved · take effect on the next dashboard start")
        QMessageBox.information(
            self, "Saved",
            "Your settings have been saved.\n\n"
            "They take effect the next time the OSINT dashboard (menu 15) starts.",
        )

    def _build_maintenance_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)

        exp_box = QGroupBox("Export project")
        exlay = QVBoxLayout(exp_box)
        exlay.addWidget(QLabel(
            "Exports the whole NexusScan folder as a ZIP to share - "
            "a clean, installable copy. NOT included: virtual environment, "
            "caches, compiled binaries and Ollama models. The recipient runs "
            "install.py and builds everything fresh."
        ))
        self.export_btn = QPushButton("Export as ZIP…")
        self.export_btn.clicked.connect(self._on_export_zip)
        exlay.addWidget(self.export_btn)
        self.maint_log = QPlainTextEdit()
        self.maint_log.setReadOnly(True)
        self.maint_log.setMaximumHeight(120)
        exlay.addWidget(self.maint_log)
        lay.addWidget(exp_box)
        lay.addStretch()
        return w

    def _on_export_zip(self):
        if self._busy():
            return
        default = os.path.join(os.path.expanduser("~"), "Nexusscan_full.zip")
        path, _ = QFileDialog.getSaveFileName(self, "Export project as ZIP",
                                              default, "ZIP archive (*.zip)")
        if not path:
            return
        if not path.lower().endswith(".zip"):
            path += ".zip"
        self.maint_log.appendPlainText(f"Exporting to {path} …")
        self.export_btn.setEnabled(False)
        self._run(self._do_export, path, done=self._after_export)

    @staticmethod
    def _do_export(path):
        try:
            n = si.export_project_zip(path)
            return True, f"{n} files to {path}"
        except Exception as e:
            return False, f"{type(e).__name__}: {e}"

    def _after_export(self, ok, msg):
        self.maint_log.appendPlainText(("✓ " if ok else "✗ ") + msg)
        self.export_btn.setEnabled(True)

    def _run(self, fn, *args, done=None):
        self._worker = FuncWorker(fn, *args)
        if done:
            self._worker.finished_result.connect(done)
        self._worker.start()
