STYLE_SHEET = """
QMainWindow, QWidget {
    background-color: #1a1a2e;
    color: #e0e0e0;
    font-family: 'Segoe UI', sans-serif;
}
QLineEdit, QTextEdit {
    background-color: #16213e;
    border: 1px solid #0f3460;
    border-radius: 8px;
    padding: 8px 12px;
    color: #e0e0e0;
    font-size: 14px;
}
QLineEdit:focus, QTextEdit:focus {
    border-color: #e94560;
}
QPushButton {
    background-color: #e94560;
    color: white;
    border: none;
    border-radius: 8px;
    padding: 10px 20px;
    font-size: 14px;
    font-weight: bold;
}
QPushButton:hover {
    background-color: #c23152;
}
QPushButton:pressed {
    background-color: #a0283f;
}
QPushButton:disabled {
    background-color: #555;
}
QPushButton[secondary="true"] {
    background-color: #0f3460;
}
QPushButton[secondary="true"]:hover {
    background-color: #1a4a7a;
}
QListWidget {
    background-color: #16213e;
    border: 1px solid #0f3460;
    border-radius: 8px;
    padding: 4px;
    outline: none;
}
QListWidget::item {
    padding: 10px;
    border-radius: 6px;
    margin: 2px;
}
QListWidget::item:selected {
    background-color: #0f3460;
}
QListWidget::item:hover {
    background-color: #1a3a5c;
}
QLabel {
    color: #e0e0e0;
}
QTabWidget::pane {
    border: 1px solid #0f3460;
    border-radius: 8px;
    background-color: #1a1a2e;
}
QTabBar::tab {
    background-color: #16213e;
    color: #e0e0e0;
    padding: 8px 16px;
    border-top-left-radius: 8px;
    border-top-right-radius: 8px;
    margin-right: 2px;
}
QTabBar::tab:selected {
    background-color: #e94560;
    color: white;
}
QSpinBox {
    background-color: #16213e;
    border: 1px solid #0f3460;
    border-radius: 8px;
    padding: 6px;
    color: #e0e0e0;
}
QCheckBox {
    color: #e0e0e0;
    spacing: 8px;
}
QScrollArea {
    border: none;
}
QFrame#chatBubbleSent {
    background-color: #e94560;
    border-radius: 12px;
    padding: 8px 12px;
}
QFrame#chatBubbleReceived {
    background-color: #0f3460;
    border-radius: 12px;
    padding: 8px 12px;
}
"""
