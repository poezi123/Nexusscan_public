from __future__ import annotations

import html
import re

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QWidget, QHBoxLayout, QVBoxLayout, QLabel, QTreeWidget, QTreeWidgetItem,
    QTextBrowser, QSplitter, QLineEdit, QTabWidget,
)

from nexus_docs import content as docs


def _render(markup: str) -> str:
    lines = markup.replace("\r\n", "\n").split("\n")
    out, in_list, in_code = [], False, False

    def inline(s: str) -> str:
        s = html.escape(s)
        s = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", s)
        s = re.sub(r"`([^`]+?)`", r"<code>\1</code>", s)
        return s

    for raw in lines:
        if raw.strip().startswith("```"):
            if in_code:
                out.append("</pre>")
                in_code = False
            else:
                if in_list:
                    out.append("</ul>"); in_list = False
                out.append("<pre>")
                in_code = True
            continue
        if in_code:
            out.append(html.escape(raw))
            continue
        line = raw.rstrip()
        if not line.strip():
            if in_list:
                out.append("</ul>"); in_list = False
            continue
        m = re.match(r"^(#{1,3})\s+(.*)$", line)
        if m:
            if in_list:
                out.append("</ul>"); in_list = False
            level = len(m.group(1))
            tag = {1: "h2", 2: "h3", 3: "h4"}[level]
            out.append(f"<{tag}>{inline(m.group(2))}</{tag}>")
            continue
        lm = re.match(r"^\s*-\s+(.*)$", line)
        if lm:
            if not in_list:
                out.append("<ul>"); in_list = True
            out.append(f"<li>{inline(lm.group(1))}</li>")
            continue
        if in_list:
            out.append("</ul>"); in_list = False
        out.append(f"<p>{inline(line)}</p>")
    if in_list:
        out.append("</ul>")
    if in_code:
        out.append("</pre>")

    style = (
        "<style>"
        "h2{color:#0b6e4f;margin:2px 0 8px} h3{color:#116a8f;margin:14px 0 4px}"
        "h4{margin:10px 0 2px} p{margin:6px 0;line-height:1.45}"
        "li{margin:3px 0} code{background:#eef;padding:1px 4px;border-radius:3px}"
        "pre{background:#f4f4f4;border:1px solid #ddd;padding:8px;white-space:pre-wrap}"
        "</style>"
    )
    return style + "\n".join(out)


class DocsPanel(QWidget):

    def __init__(self, entries, filter_hint, parent=None):
        super().__init__(parent)
        self._entries = entries
        lay = QVBoxLayout(self)

        self.filter = QLineEdit()
        self.filter.setPlaceholderText(filter_hint)
        self.filter.textChanged.connect(self._apply_filter)
        lay.addWidget(self.filter)

        splitter = QSplitter(Qt.Horizontal)
        self.tree = QTreeWidget()
        self.tree.setHeaderHidden(True)
        self.tree.setMinimumWidth(280)
        self.tree.currentItemChanged.connect(self._on_select)
        splitter.addWidget(self.tree)

        self.view = QTextBrowser()
        self.view.setOpenExternalLinks(True)
        splitter.addWidget(self.view)
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        lay.addWidget(splitter, stretch=1)

        self._populate()

    def _populate(self):
        self.tree.clear()
        by_cat = {}
        for entry in self._entries:
            by_cat.setdefault(entry["category"], []).append(entry)
        first_child = None
        for category, entries in by_cat.items():
            top = QTreeWidgetItem([category])
            top.setFlags(top.flags() & ~Qt.ItemIsSelectable)
            font = top.font(0); font.setBold(True); top.setFont(0, font)
            self.tree.addTopLevelItem(top)
            for e in entries:
                child = QTreeWidgetItem([e["title"]])
                child.setData(0, Qt.UserRole, e)
                top.addChild(child)
                if first_child is None:
                    first_child = child
            top.setExpanded(True)
        if first_child:
            self.tree.setCurrentItem(first_child)

    def _on_select(self, current, _previous):
        if not current:
            return
        entry = current.data(0, Qt.UserRole)
        if entry:
            self.view.setHtml(_render(entry["body"]))

    def _apply_filter(self, text):
        text = text.strip().lower()
        for i in range(self.tree.topLevelItemCount()):
            top = self.tree.topLevelItem(i)
            any_visible = False
            for j in range(top.childCount()):
                child = top.child(j)
                match = text in child.text(0).lower()
                child.setHidden(bool(text) and not match)
                any_visible = any_visible or not child.isHidden()
            top.setHidden(bool(text) and not any_visible)


class DocsWindow(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("NexusScan documentation")
        self.resize(960, 660)

        root = QVBoxLayout(self)
        header = QLabel("📚  NexusScan documentation")
        header.setStyleSheet("font-size: 16px; font-weight: bold; padding: 4px;")
        root.addWidget(header)

        tabs = QTabWidget()
        tabs.addTab(DocsPanel(docs.ENTRIES, "Filter modules…"), "How it works")
        tabs.addTab(DocsPanel(docs.USAGE_ENTRIES, "Filter guides…"), "Usage")
        root.addWidget(tabs, stretch=1)
