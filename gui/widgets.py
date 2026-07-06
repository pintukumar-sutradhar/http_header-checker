"""
gui/widgets.py
================
Reusable, styled Qt widgets used throughout the application: stat cards,
severity/status badges, a circular-ish score gauge, a findings table, and
a live scan-stage progress tracker.
"""
from __future__ import annotations

from typing import Optional

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont, QColor
from PySide6.QtWidgets import (
    QWidget, QLabel, QVBoxLayout, QHBoxLayout, QFrame, QSizePolicy,
    QTableWidget, QTableWidgetItem, QHeaderView, QProgressBar, QAbstractItemView,
)

from utils.constants import (
    COLOR_CARD, COLOR_BORDER, COLOR_TEXT, COLOR_TEXT_MUTED, COLOR_GREEN,
    COLOR_ORANGE, COLOR_RED, COLOR_BLUE,
)


class StatCard(QFrame):
    """A small rounded card showing a label + value, used on the dashboard."""

    def __init__(self, title: str, value: str = "—", accent: str = COLOR_BLUE, parent=None):
        super().__init__(parent)
        self.setObjectName("StatCard")
        self.setStyleSheet(f"""
            #StatCard {{
                background-color: {COLOR_CARD};
                border: 1px solid {COLOR_BORDER};
                border-radius: 10px;
            }}
        """)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(4)

        self.title_label = QLabel(title.upper())
        self.title_label.setStyleSheet(f"color:{COLOR_TEXT_MUTED}; font-size: 10px; font-weight:600; letter-spacing: 0.5px; border:none;")

        self.value_label = QLabel(value)
        self.value_label.setStyleSheet(f"color:{accent}; font-size: 15px; font-weight:700; border:none;")
        self.value_label.setWordWrap(True)

        layout.addWidget(self.title_label)
        layout.addWidget(self.value_label)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)

    def set_value(self, value: str, accent: Optional[str] = None) -> None:
        self.value_label.setText(value if value else "—")
        if accent:
            self.value_label.setStyleSheet(f"color:{accent}; font-size: 15px; font-weight:700; border:none;")


class Badge(QLabel):
    """A small colored pill badge, e.g. for severities or header statuses."""

    def __init__(self, text: str, color: str = COLOR_BLUE, parent=None):
        super().__init__(text, parent)
        self.set_style(color)
        self.setAlignment(Qt.AlignCenter)

    def set_style(self, color: str) -> None:
        self.setStyleSheet(f"""
            QLabel {{
                background-color: {color}22;
                color: {color};
                border: 1px solid {color};
                border-radius: 9px;
                padding: 2px 10px;
                font-weight: 600;
                font-size: 11px;
            }}
        """)


class ScoreGauge(QFrame):
    """Large circular-styled score display with grade and color coding."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("ScoreGauge")
        self.setFixedSize(170, 170)
        self.setStyleSheet(f"""
            #ScoreGauge {{
                background-color: {COLOR_CARD};
                border: 4px solid {COLOR_GREEN};
                border-radius: 85px;
            }}
        """)
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignCenter)

        self.score_label = QLabel("--")
        self.score_label.setAlignment(Qt.AlignCenter)
        self.score_label.setStyleSheet(f"color:{COLOR_GREEN}; font-size: 42px; font-weight: 800; border:none;")

        self.grade_label = QLabel("Grade: --")
        self.grade_label.setAlignment(Qt.AlignCenter)
        self.grade_label.setStyleSheet(f"color:{COLOR_TEXT_MUTED}; font-size: 13px; font-weight: 600; border:none;")

        layout.addWidget(self.score_label)
        layout.addWidget(self.grade_label)

    def set_score(self, score: int, grade: str, color: str) -> None:
        self.score_label.setText(str(score))
        self.score_label.setStyleSheet(f"color:{color}; font-size: 42px; font-weight: 800; border:none;")
        self.grade_label.setText(f"Grade: {grade}")
        self.setStyleSheet(f"""
            #ScoreGauge {{
                background-color: {COLOR_CARD};
                border: 4px solid {color};
                border-radius: 85px;
            }}
        """)


class StageProgressBar(QWidget):
    """Shows the live scan-stage checklist (Resolving DNS -> ... -> Completed)."""

    STAGES = [
        "Resolving DNS", "Connecting", "TLS Handshake", "Sending Request",
        "Receiving Headers", "Parsing", "Analyzing", "Generating Report", "Completed",
    ]

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)
        self._labels: dict[str, QLabel] = {}
        for stage in self.STAGES:
            lbl = QLabel(stage)
            lbl.setStyleSheet(f"""
                QLabel {{
                    background-color: {COLOR_CARD};
                    color: {COLOR_TEXT_MUTED};
                    border: 1px solid {COLOR_BORDER};
                    border-radius: 8px;
                    padding: 4px 8px;
                    font-size: 10px;
                    font-weight: 600;
                }}
            """)
            self._labels[stage] = lbl
            layout.addWidget(lbl)
        layout.addStretch()

    def set_stage(self, stage_name: str) -> None:
        reached = False
        for stage in self.STAGES:
            lbl = self._labels[stage]
            if stage == stage_name:
                reached = True
                if stage_name == "Completed":
                    color = COLOR_GREEN
                else:
                    color = COLOR_BLUE
                lbl.setStyleSheet(f"""
                    QLabel {{
                        background-color: {color}33;
                        color: {color};
                        border: 1px solid {color};
                        border-radius: 8px;
                        padding: 4px 8px;
                        font-size: 10px;
                        font-weight: 700;
                    }}
                """)
            elif not reached:
                lbl.setStyleSheet(f"""
                    QLabel {{
                        background-color: {COLOR_GREEN}22;
                        color: {COLOR_GREEN};
                        border: 1px solid {COLOR_GREEN};
                        border-radius: 8px;
                        padding: 4px 8px;
                        font-size: 10px;
                        font-weight: 600;
                    }}
                """)
            else:
                lbl.setStyleSheet(f"""
                    QLabel {{
                        background-color: {COLOR_CARD};
                        color: {COLOR_TEXT_MUTED};
                        border: 1px solid {COLOR_BORDER};
                        border-radius: 8px;
                        padding: 4px 8px;
                        font-size: 10px;
                        font-weight: 600;
                    }}
                """)

    def reset(self) -> None:
        for stage, lbl in self._labels.items():
            lbl.setStyleSheet(f"""
                QLabel {{
                    background-color: {COLOR_CARD};
                    color: {COLOR_TEXT_MUTED};
                    border: 1px solid {COLOR_BORDER};
                    border-radius: 8px;
                    padding: 4px 8px;
                    font-size: 10px;
                    font-weight: 600;
                }}
            """)


def make_table(headers: list[str]) -> QTableWidget:
    """Factory for a consistently-styled read-only table widget."""
    table = QTableWidget()
    table.setColumnCount(len(headers))
    table.setHorizontalHeaderLabels(headers)
    table.horizontalHeader().setStretchLastSection(True)
    table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
    table.verticalHeader().setVisible(False)
    table.setEditTriggers(QAbstractItemView.NoEditTriggers)
    table.setSelectionBehavior(QAbstractItemView.SelectRows)
    table.setAlternatingRowColors(True)
    table.setWordWrap(True)
    return table


SEVERITY_COLORS = {
    "Critical": COLOR_RED,
    "High": "#F97316",
    "Medium": COLOR_ORANGE,
    "Low": COLOR_BLUE,
    "Informational": COLOR_TEXT_MUTED,
}

STATUS_COLORS = {
    "Present": COLOR_GREEN,
    "Missing": COLOR_RED,
    "Weak": COLOR_ORANGE,
    "Misconfigured": "#F97316",
    "Deprecated": COLOR_TEXT_MUTED,
}
