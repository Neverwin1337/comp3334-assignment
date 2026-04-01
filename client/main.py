import sys
import os
import json
import base64
import time
from datetime import datetime, timedelta

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTextEdit, QListWidget, QListWidgetItem,
    QStackedWidget, QMessageBox, QSplitter, QFrame, QSpinBox, QCheckBox,
    QDialog, QFormLayout, QTabWidget, QScrollArea, QSizePolicy,
)
from PySide6.QtCore import Qt, QTimer, Signal, QObject, QThread, QSize
from PySide6.QtGui import QPixmap, QFont, QColor, QIcon

from api_client import ApiClient
from crypto_utils import KeyBundle, SessionCipher, encrypt_backup, decrypt_backup

DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')
os.makedirs(DATA_DIR, exist_ok=True)

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


class SessionManager:
    def __init__(self, username):
        self.username = username
        self.sessions = {}
        self.session_file = os.path.join(DATA_DIR, f'{username}_sessions.json')
        self._load()

    def _load(self):
        if os.path.exists(self.session_file):
            with open(self.session_file, 'r') as f:
                self.sessions = json.load(f)

    def _save(self):
        with open(self.session_file, 'w') as f:
            json.dump(self.sessions, f, indent=2)

    def has_session(self, friend_id):
        return str(friend_id) in self.sessions

    def save_session(self, friend_id, shared_key_b64):
        self.sessions[str(friend_id)] = {'shared_key': shared_key_b64}
        self._save()

    def get_session(self, friend_id):
        data = self.sessions.get(str(friend_id))
        if data:
            cipher = SessionCipher()
            cipher.shared_key = base64.b64decode(data['shared_key'])
            return cipher
        return None


class MessageStore:
    def __init__(self, username):
        self.username = username
        self.store_file = os.path.join(DATA_DIR, f'{username}_messages.json')
        self.messages = {}
        self._load()

    def _load(self):
        if os.path.exists(self.store_file):
            with open(self.store_file, 'r') as f:
                self.messages = json.load(f)

    def _save(self):
        with open(self.store_file, 'w') as f:
            json.dump(self.messages, f, indent=2)

    def add_message(self, friend_id, msg):
        key = str(friend_id)
        if key not in self.messages:
            self.messages[key] = []
        self.messages[key].append(msg)
        self._save()

    def get_messages(self, friend_id):
        return self.messages.get(str(friend_id), [])

    def remove_expired(self):
        now = time.time()
        changed = False
        for key in list(self.messages.keys()):
            original_len = len(self.messages[key])
            self.messages[key] = [
                m for m in self.messages[key]
                if not m.get('expire_at') or m['expire_at'] > now
            ]
            if len(self.messages[key]) != original_len:
                changed = True
        if changed:
            self._save()


class PollingWorker(QObject):
    new_messages = Signal(list)
    new_friend_requests = Signal(list)
    friends_updated = Signal(list)
    conversations_updated = Signal(list)

    def __init__(self, api_client):
        super().__init__()
        self.api = api_client
        self.running = True

    def poll(self):
        while self.running:
            try:
                data, status = self.api.fetch_messages()
                if status == 200 and data.get('messages'):
                    self.new_messages.emit(data['messages'])

                data, status = self.api.get_friend_requests()
                if status == 200 and data.get('requests'):
                    self.new_friend_requests.emit(data['requests'])

                data, status = self.api.list_friends()
                if status == 200:
                    self.friends_updated.emit(data['friends'])

                data, status = self.api.get_conversations()
                if status == 200:
                    self.conversations_updated.emit(data['conversations'])
            except Exception:
                pass
            time.sleep(1)

    def stop(self):
        self.running = False


class LoginWindow(QWidget):
    login_success = Signal(dict)

    def __init__(self, api_client):
        super().__init__()
        self.api = api_client
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignCenter)
        layout.setSpacing(16)
        layout.setContentsMargins(60, 40, 60, 40)

        title = QLabel('SecureChat')
        title.setFont(QFont('Segoe UI', 28, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet('color: #e94560;')
        layout.addWidget(title)

        subtitle = QLabel('End-to-End Encrypted Messaging')
        subtitle.setAlignment(Qt.AlignCenter)
        subtitle.setStyleSheet('color: #888; font-size: 14px;')
        layout.addWidget(subtitle)

        layout.addSpacing(20)

        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText('Username')
        self.username_input.setMinimumHeight(44)
        layout.addWidget(self.username_input)

        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText('Password')
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setMinimumHeight(44)
        layout.addWidget(self.password_input)

        self.otp_input = QLineEdit()
        self.otp_input.setPlaceholderText('OTP Code (6 digits)')
        self.otp_input.setMaxLength(6)
        self.otp_input.setMinimumHeight(44)
        layout.addWidget(self.otp_input)

        self.login_btn = QPushButton('Login')
        self.login_btn.setMinimumHeight(44)
        self.login_btn.clicked.connect(self._on_login)
        layout.addWidget(self.login_btn)

        self.register_btn = QPushButton('Create Account')
        self.register_btn.setProperty('secondary', True)
        self.register_btn.setMinimumHeight(44)
        self.register_btn.clicked.connect(self._on_register)
        layout.addWidget(self.register_btn)

        self.status_label = QLabel('')
        self.status_label.setAlignment(Qt.AlignCenter)
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

    def _on_login(self):
        username = self.username_input.text().strip()
        password = self.password_input.text()
        otp_code = self.otp_input.text().strip()

        if not username or not password or not otp_code:
            self.status_label.setText('All fields are required')
            self.status_label.setStyleSheet('color: #e94560;')
            return

        self.login_btn.setEnabled(False)
        try:
            data, status = self.api.login(username, password, otp_code)
            if status == 200:
                self.login_success.emit(data)
            else:
                self.status_label.setText(data.get('error', 'Login failed'))
                self.status_label.setStyleSheet('color: #e94560;')
        except Exception as e:
            self.status_label.setText(f'Connection error: {e}')
            self.status_label.setStyleSheet('color: #e94560;')
        finally:
            self.login_btn.setEnabled(True)

    def _on_register(self):
        username = self.username_input.text().strip()
        password = self.password_input.text()

        if not username or not password:
            self.status_label.setText('Username and password required')
            self.status_label.setStyleSheet('color: #e94560;')
            return

        if len(password) < 8:
            self.status_label.setText('Password must be at least 8 characters')
            self.status_label.setStyleSheet('color: #e94560;')
            return

        self.register_btn.setEnabled(False)
        try:
            data, status = self.api.register(username, password)
            if status == 201:
                dlg = QDialog(self)
                dlg.setWindowTitle('Registration Successful')
                dlg.setMinimumSize(400, 500)
                layout = QVBoxLayout(dlg)

                layout.addWidget(QLabel('Scan this QR code with your authenticator app:'))

                qr_label = QLabel()
                qr_bytes = base64.b64decode(data['qr_code'])
                pixmap = QPixmap()
                pixmap.loadFromData(qr_bytes)
                qr_label.setPixmap(pixmap.scaled(300, 300, Qt.KeepAspectRatio))
                qr_label.setAlignment(Qt.AlignCenter)
                layout.addWidget(qr_label)

                secret_label = QLabel(f"Secret: {data['otp_secret']}")
                secret_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
                secret_label.setAlignment(Qt.AlignCenter)
                layout.addWidget(secret_label)

                ok_btn = QPushButton('Done')
                ok_btn.clicked.connect(dlg.accept)
                layout.addWidget(ok_btn)

                dlg.exec()

                self.status_label.setText('Registration successful! Enter OTP to login.')
                self.status_label.setStyleSheet('color: #4ecdc4;')
            else:
                self.status_label.setText(data.get('error', 'Registration failed'))
                self.status_label.setStyleSheet('color: #e94560;')
        except Exception as e:
            self.status_label.setText(f'Connection error: {e}')
            self.status_label.setStyleSheet('color: #e94560;')
        finally:
            self.register_btn.setEnabled(True)


class ChatBubble(QFrame):
    def __init__(self, text, is_sent, timestamp='', status='', self_destruct=None, parent=None):
        super().__init__(parent)
        self.setObjectName('chatBubbleSent' if is_sent else 'chatBubbleReceived')

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(4)

        msg_label = QLabel(text)
        msg_label.setWordWrap(True)
        msg_label.setStyleSheet('color: white; font-size: 14px; background: transparent;')
        layout.addWidget(msg_label)

        meta_parts = []
        if timestamp:
            meta_parts.append(timestamp)
        if status:
            status_icons = {'sent': '✓', 'delivered': '✓✓', 'read': '✓✓'}
            meta_parts.append(status_icons.get(status, status))
        if self_destruct:
            meta_parts.append(f'💣 {self_destruct}s')

        if meta_parts:
            meta_label = QLabel(' · '.join(meta_parts))
            meta_label.setStyleSheet('color: rgba(255,255,255,0.6); font-size: 11px; background: transparent;')
            meta_label.setAlignment(Qt.AlignRight if is_sent else Qt.AlignLeft)
            layout.addWidget(meta_label)


class ChatWidget(QWidget):
    def __init__(self, api_client, my_user_id, friend_id, friend_name, session_mgr, message_store, key_bundle):
        super().__init__()
        self.api = api_client
        self.my_user_id = my_user_id
        self.friend_id = friend_id
        self.friend_name = friend_name
        self.session_mgr = session_mgr
        self.message_store = message_store
        self.key_bundle = key_bundle
        self._setup_ui()
        self._load_messages()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        header = QFrame()
        header.setStyleSheet('background-color: #16213e; padding: 12px;')
        header_layout = QHBoxLayout(header)
        name_label = QLabel(f'  {self.friend_name}')
        name_label.setFont(QFont('Segoe UI', 16, QFont.Bold))
        name_label.setStyleSheet('background: transparent;')
        header_layout.addWidget(name_label)
        header_layout.addStretch()

        lock_label = QLabel('🔒 E2EE')
        lock_label.setStyleSheet('color: #4ecdc4; font-size: 12px; background: transparent;')
        header_layout.addWidget(lock_label)
        layout.addWidget(header)

        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        self.messages_widget = QWidget()
        self.messages_layout = QVBoxLayout(self.messages_widget)
        self.messages_layout.setAlignment(Qt.AlignTop)
        self.messages_layout.setSpacing(8)
        self.messages_layout.setContentsMargins(16, 16, 16, 16)
        self.messages_layout.addStretch()

        self.scroll_area.setWidget(self.messages_widget)
        layout.addWidget(self.scroll_area)

        input_frame = QFrame()
        input_frame.setStyleSheet('background-color: #16213e; padding: 8px;')
        input_layout = QHBoxLayout(input_frame)
        input_layout.setSpacing(8)

        left_col = QVBoxLayout()
        self.message_input = QLineEdit()
        self.message_input.setPlaceholderText('Type a message...')
        self.message_input.setMinimumHeight(40)
        self.message_input.returnPressed.connect(self._send_message)
        self.message_input.setStyleSheet(self.message_input.styleSheet() + 'background: #1a1a2e;')
        left_col.addWidget(self.message_input)

        options_layout = QHBoxLayout()
        self.self_destruct_cb = QCheckBox('Self-destruct')
        self.self_destruct_cb.setStyleSheet('background: transparent;')
        options_layout.addWidget(self.self_destruct_cb)

        self.destruct_time = QSpinBox()
        self.destruct_time.setRange(5, 3600)
        self.destruct_time.setValue(30)
        self.destruct_time.setSuffix('s')
        self.destruct_time.setFixedWidth(80)
        options_layout.addWidget(self.destruct_time)
        options_layout.addStretch()
        left_col.addLayout(options_layout)

        input_layout.addLayout(left_col, 1)

        self.send_btn = QPushButton('Send')
        self.send_btn.setMinimumHeight(40)
        self.send_btn.setFixedWidth(80)
        self.send_btn.clicked.connect(self._send_message)
        input_layout.addWidget(self.send_btn, 0, Qt.AlignTop)

        layout.addWidget(input_frame)

    def _get_or_create_session(self):
        cipher = self.session_mgr.get_session(self.friend_id)
        if cipher:
            return cipher, None

        bundle_data, status = self.api.get_key_bundle(self.friend_id)
        if status != 200:
            raise Exception(f'Failed to get key bundle: {bundle_data.get("error", "Unknown")}')

        cipher = SessionCipher()
        ephemeral_pub_b64 = cipher.init_sender(self.key_bundle, bundle_data)

        shared_key_b64 = base64.b64encode(cipher.shared_key).decode('utf-8')
        self.session_mgr.save_session(self.friend_id, shared_key_b64)

        ik_data = self.key_bundle.get_upload_data()['identity_public_key']
        initial_info = json.dumps({
            'sender_ik': ik_data,
            'ephemeral_key': ephemeral_pub_b64,
            'otpk_key_id': bundle_data['one_time_prekey']['key_id'] if bundle_data.get('one_time_prekey') else None,
        })
        return cipher, initial_info

    def _send_message(self):
        text = self.message_input.text().strip()
        if not text:
            return

        self.send_btn.setEnabled(False)
        try:
            cipher, initial_info = self._get_or_create_session()

            self_destruct_seconds = None
            if self.self_destruct_cb.isChecked():
                self_destruct_seconds = self.destruct_time.value()

            ciphertext, nonce = cipher.encrypt(text)

            msg_type = 'initial' if initial_info else 'normal'
            ephemeral_key = initial_info if initial_info else None

            data, status = self.api.send_message(
                receiver_id=self.friend_id,
                ciphertext=ciphertext,
                nonce=nonce,
                ephemeral_key=ephemeral_key,
                message_type=msg_type,
                self_destruct_seconds=self_destruct_seconds,
            )

            if status == 201:
                now = time.time()
                msg_data = {
                    'sender_id': self.my_user_id,
                    'text': text,
                    'timestamp': datetime.utcnow().strftime('%H:%M'),
                    'status': 'sent',
                    'message_id': data['message_id'],
                    'self_destruct_seconds': self_destruct_seconds,
                }
                if self_destruct_seconds:
                    msg_data['expire_at'] = now + self_destruct_seconds

                self.message_store.add_message(self.friend_id, msg_data)
                self._add_bubble(text, True, msg_data['timestamp'], 'sent', self_destruct_seconds)
                self.message_input.clear()
            else:
                QMessageBox.warning(self, 'Error', data.get('error', 'Failed to send'))
        except Exception as e:
            QMessageBox.warning(self, 'Error', str(e))
        finally:
            self.send_btn.setEnabled(True)

    def _add_bubble(self, text, is_sent, timestamp='', status='', self_destruct=None):
        bubble = ChatBubble(text, is_sent, timestamp, status, self_destruct)
        bubble.setMaximumWidth(500)

        wrapper = QHBoxLayout()
        if is_sent:
            wrapper.addStretch()
            wrapper.addWidget(bubble)
        else:
            wrapper.addWidget(bubble)
            wrapper.addStretch()

        idx = self.messages_layout.count() - 1
        self.messages_layout.insertLayout(idx, wrapper)

        QTimer.singleShot(50, lambda: self.scroll_area.verticalScrollBar().setValue(
            self.scroll_area.verticalScrollBar().maximum()
        ))

    def _load_messages(self):
        messages = self.message_store.get_messages(self.friend_id)
        for msg in messages:
            is_sent = msg['sender_id'] == self.my_user_id
            self._add_bubble(
                msg['text'],
                is_sent,
                msg.get('timestamp', ''),
                msg.get('status', ''),
                msg.get('self_destruct_seconds'),
            )

    def receive_message(self, text, timestamp, self_destruct_seconds=None):
        now = time.time()
        msg_data = {
            'sender_id': self.friend_id,
            'text': text,
            'timestamp': timestamp,
            'status': 'delivered',
            'self_destruct_seconds': self_destruct_seconds,
        }
        if self_destruct_seconds:
            msg_data['expire_at'] = now + self_destruct_seconds

        self.message_store.add_message(self.friend_id, msg_data)
        self._add_bubble(text, False, timestamp, '', self_destruct_seconds)


class MainWindow(QMainWindow):
    def __init__(self, api_client, user_data):
        super().__init__()
        self.api = api_client
        self.user_id = user_data['user_id']
        self.username = user_data['username']
        self.setWindowTitle(f'SecureChat - {self.username}')
        self.setMinimumSize(900, 600)

        self.key_bundle = KeyBundle()
        self.session_mgr = SessionManager(self.username)
        self.message_store = MessageStore(self.username)
        self.chat_widgets = {}

        self._init_keys()
        self._setup_ui()
        self._start_polling()
        self._refresh_friends()
        self._refresh_conversations()

        self.destruct_timer = QTimer()
        self.destruct_timer.timeout.connect(self._check_expired_messages)
        self.destruct_timer.start(5000)

    def _init_keys(self):
        key_file = os.path.join(DATA_DIR, f'{self.username}_keys.json')
        session_file = os.path.join(DATA_DIR, f'{self.username}_sessions.json')

        if os.path.exists(key_file):
            self.key_bundle.load_from_file(key_file)
        else:
            restored = self._try_restore_backup(key_file, session_file)
            if not restored:
                self.key_bundle.generate()
                self.key_bundle.save_to_file(key_file)

        upload_data = self.key_bundle.get_upload_data()
        self.api.upload_keys(upload_data)

    def _try_restore_backup(self, key_file, session_file):
        try:
            data, status = self.api.download_backup()
            if status != 200:
                return False
        except Exception:
            return False

        dlg = QDialog(self)
        dlg.setWindowTitle('Key Backup Found')
        dlg.setMinimumWidth(380)
        layout = QVBoxLayout(dlg)

        layout.addWidget(QLabel('A key backup was found on the server.\nEnter your backup passphrase to restore:'))

        passphrase_input = QLineEdit()
        passphrase_input.setPlaceholderText('Backup passphrase')
        passphrase_input.setEchoMode(QLineEdit.Password)
        passphrase_input.setMinimumHeight(40)
        layout.addWidget(passphrase_input)

        btn_layout = QHBoxLayout()
        restore_btn = QPushButton('Restore')
        restore_btn.setMinimumHeight(40)
        skip_btn = QPushButton('Skip (New Keys)')
        skip_btn.setProperty('secondary', True)
        skip_btn.setMinimumHeight(40)
        btn_layout.addWidget(restore_btn)
        btn_layout.addWidget(skip_btn)
        layout.addLayout(btn_layout)

        status_label = QLabel('')
        status_label.setWordWrap(True)
        layout.addWidget(status_label)

        result = {'restored': False}

        def on_restore():
            passphrase = passphrase_input.text()
            if not passphrase:
                status_label.setText('Passphrase is required')
                status_label.setStyleSheet('color: #e94560;')
                return
            try:
                plaintext = decrypt_backup(
                    data['encrypted_data'], data['nonce'], data['salt'], passphrase,
                )
                backup_data = json.loads(plaintext)

                with open(key_file, 'w') as f:
                    json.dump(backup_data['keys'], f, indent=2)
                self.key_bundle.load_from_file(key_file)

                if backup_data.get('sessions'):
                    with open(session_file, 'w') as f:
                        json.dump(backup_data['sessions'], f, indent=2)
                    self.session_mgr = SessionManager(self.username)

                result['restored'] = True
                dlg.accept()
            except Exception:
                status_label.setText('Wrong passphrase or corrupted backup')
                status_label.setStyleSheet('color: #e94560;')

        restore_btn.clicked.connect(on_restore)
        skip_btn.clicked.connect(dlg.reject)
        dlg.exec()
        return result['restored']

    def _on_backup_keys(self):
        dlg = QDialog(self)
        dlg.setWindowTitle('Backup Keys')
        dlg.setMinimumWidth(380)
        layout = QVBoxLayout(dlg)

        layout.addWidget(QLabel(
            'Encrypt your keys with a passphrase and upload to server.\n'
            'Use this to restore keys on a new device.'
        ))

        passphrase_input = QLineEdit()
        passphrase_input.setPlaceholderText('Passphrase (min 8 chars)')
        passphrase_input.setEchoMode(QLineEdit.Password)
        passphrase_input.setMinimumHeight(40)
        layout.addWidget(passphrase_input)

        confirm_input = QLineEdit()
        confirm_input.setPlaceholderText('Confirm passphrase')
        confirm_input.setEchoMode(QLineEdit.Password)
        confirm_input.setMinimumHeight(40)
        layout.addWidget(confirm_input)

        status_label = QLabel('')
        status_label.setWordWrap(True)
        layout.addWidget(status_label)

        upload_btn = QPushButton('Encrypt & Upload')
        upload_btn.setMinimumHeight(40)
        layout.addWidget(upload_btn)

        def on_upload():
            passphrase = passphrase_input.text()
            confirm = confirm_input.text()
            if len(passphrase) < 8:
                status_label.setText('Passphrase must be at least 8 characters')
                status_label.setStyleSheet('color: #e94560;')
                return
            if passphrase != confirm:
                status_label.setText('Passphrases do not match')
                status_label.setStyleSheet('color: #e94560;')
                return

            try:
                key_file = os.path.join(DATA_DIR, f'{self.username}_keys.json')
                with open(key_file, 'r') as f:
                    keys_data = json.load(f)

                sessions_data = self.session_mgr.sessions

                backup_payload = json.dumps({
                    'keys': keys_data,
                    'sessions': sessions_data,
                })

                ct, nonce, salt = encrypt_backup(backup_payload, passphrase)
                resp, st = self.api.upload_backup(ct, nonce, salt)

                if st == 200:
                    status_label.setText('Backup uploaded successfully!')
                    status_label.setStyleSheet('color: #4ecdc4;')
                    upload_btn.setEnabled(False)
                else:
                    status_label.setText(resp.get('error', 'Upload failed'))
                    status_label.setStyleSheet('color: #e94560;')
            except Exception as e:
                status_label.setText(f'Error: {e}')
                status_label.setStyleSheet('color: #e94560;')

        upload_btn.clicked.connect(on_upload)
        dlg.exec()

    def _setup_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QHBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        left_panel = QFrame()
        left_panel.setFixedWidth(300)
        left_panel.setStyleSheet('background-color: #16213e;')
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(0)

        user_frame = QFrame()
        user_frame.setStyleSheet('background-color: #0f3460; padding: 12px;')
        user_layout = QHBoxLayout(user_frame)
        user_label = QLabel(f'  {self.username}')
        user_label.setFont(QFont('Segoe UI', 14, QFont.Bold))
        user_label.setStyleSheet('background: transparent;')
        user_layout.addWidget(user_label)
        user_layout.addStretch()

        backup_btn = QPushButton('Backup')
        backup_btn.setFixedWidth(70)
        backup_btn.setStyleSheet('font-size: 12px; padding: 6px; background: #4ecdc4; color: #1a1a2e;')
        backup_btn.clicked.connect(self._on_backup_keys)
        user_layout.addWidget(backup_btn)

        logout_btn = QPushButton('Logout')
        logout_btn.setFixedWidth(70)
        logout_btn.setStyleSheet('font-size: 12px; padding: 6px; background: #e94560;')
        logout_btn.clicked.connect(self._on_logout)
        user_layout.addWidget(logout_btn)
        left_layout.addWidget(user_frame)

        self.tabs = QTabWidget()
        self.tabs.setStyleSheet('QTabWidget { background: transparent; }')

        chats_tab = QWidget()
        chats_layout = QVBoxLayout(chats_tab)
        chats_layout.setContentsMargins(8, 8, 8, 8)

        self.conversation_list = QListWidget()
        self.conversation_list.itemClicked.connect(self._on_conversation_clicked)
        chats_layout.addWidget(self.conversation_list)
        self.tabs.addTab(chats_tab, 'Chats')

        contacts_tab = QWidget()
        contacts_layout = QVBoxLayout(contacts_tab)
        contacts_layout.setContentsMargins(8, 8, 8, 8)

        add_layout = QHBoxLayout()
        self.add_friend_input = QLineEdit()
        self.add_friend_input.setPlaceholderText('Add friend...')
        self.add_friend_input.setMinimumHeight(36)
        add_layout.addWidget(self.add_friend_input)

        add_btn = QPushButton('+')
        add_btn.setFixedSize(36, 36)
        add_btn.clicked.connect(self._on_add_friend)
        add_layout.addWidget(add_btn)
        contacts_layout.addLayout(add_layout)

        self.friends_list = QListWidget()
        self.friends_list.itemClicked.connect(self._on_friend_clicked)
        contacts_layout.addWidget(self.friends_list)
        self.tabs.addTab(contacts_tab, 'Contacts')

        requests_tab = QWidget()
        requests_layout = QVBoxLayout(requests_tab)
        requests_layout.setContentsMargins(8, 8, 8, 8)

        self.requests_list = QListWidget()
        requests_layout.addWidget(self.requests_list)

        refresh_req_btn = QPushButton('Refresh')
        refresh_req_btn.setProperty('secondary', True)
        refresh_req_btn.clicked.connect(self._refresh_requests)
        requests_layout.addWidget(refresh_req_btn)
        self.tabs.addTab(requests_tab, 'Requests')

        left_layout.addWidget(self.tabs)
        main_layout.addWidget(left_panel)

        self.chat_stack = QStackedWidget()

        placeholder = QWidget()
        ph_layout = QVBoxLayout(placeholder)
        ph_layout.setAlignment(Qt.AlignCenter)
        ph_label = QLabel('Select a conversation to start chatting')
        ph_label.setStyleSheet('color: #555; font-size: 16px;')
        ph_label.setAlignment(Qt.AlignCenter)
        ph_layout.addWidget(ph_label)

        lock_label = QLabel('🔒')
        lock_label.setFont(QFont('Segoe UI', 48))
        lock_label.setAlignment(Qt.AlignCenter)
        lock_label.setStyleSheet('background: transparent;')
        ph_layout.addWidget(lock_label)

        self.chat_stack.addWidget(placeholder)
        main_layout.addWidget(self.chat_stack)

    def _start_polling(self):
        self.poll_thread = QThread()
        self.poll_worker = PollingWorker(self.api)
        self.poll_worker.moveToThread(self.poll_thread)
        self.poll_worker.new_messages.connect(self._on_new_messages)
        self.poll_worker.new_friend_requests.connect(self._on_new_friend_requests)
        self.poll_worker.friends_updated.connect(self._on_friends_updated)
        self.poll_worker.conversations_updated.connect(self._on_conversations_updated)
        self.poll_thread.started.connect(self.poll_worker.poll)
        self.poll_thread.start()

    def _on_new_messages(self, messages):
        ack_ids = []
        for msg in messages:
            sender_id = msg['sender_id']
            try:
                plaintext = self._decrypt_message(msg)
                ts = datetime.fromisoformat(msg['created_at']).strftime('%H:%M')
                sd = msg.get('self_destruct_seconds')

                if sender_id in self.chat_widgets:
                    self.chat_widgets[sender_id].receive_message(plaintext, ts, sd)
                else:
                    now = time.time()
                    msg_data = {
                        'sender_id': sender_id,
                        'text': plaintext,
                        'timestamp': ts,
                        'status': 'delivered',
                        'self_destruct_seconds': sd,
                    }
                    if sd:
                        msg_data['expire_at'] = now + sd
                    self.message_store.add_message(sender_id, msg_data)

                ack_ids.append(msg['message_id'])
            except Exception as e:
                import traceback
                print(f'Decrypt error for message {msg["message_id"]}: {e}')
                traceback.print_exc()

        if ack_ids:
            try:
                self.api.ack_messages(ack_ids)
            except Exception:
                pass

        self._refresh_conversations()

    def _decrypt_message(self, msg):
        sender_id = msg['sender_id']

        if msg['message_type'] == 'initial' and msg.get('ephemeral_key'):
            info = json.loads(msg['ephemeral_key'])
            cipher = SessionCipher()
            cipher.init_receiver(
                self.key_bundle,
                info['sender_ik'],
                info['ephemeral_key'],
                info.get('otpk_key_id'),
            )
            shared_key_b64 = base64.b64encode(cipher.shared_key).decode('utf-8')
            self.session_mgr.save_session(sender_id, shared_key_b64)
            return cipher.decrypt(msg['ciphertext'], msg['nonce'])
        else:
            cipher = self.session_mgr.get_session(sender_id)
            if not cipher:
                raise Exception('No session found for this sender')
            return cipher.decrypt(msg['ciphertext'], msg['nonce'])

    def _on_new_friend_requests(self, requests):
        self._update_requests_list(requests)

    def _on_friends_updated(self, friends):
        self.friends_list.clear()
        self._friends_data = friends
        for f in friends:
            status_dot = '🟢' if f['is_online'] else '⚫'
            item = QListWidgetItem(f'{status_dot} {f["username"]}')
            item.setData(Qt.UserRole, f)
            self.friends_list.addItem(item)

    def _on_conversations_updated(self, conversations):
        self.conversation_list.clear()
        for conv in conversations:
            unread = conv['unread_count']
            badge = f' ({unread})' if unread > 0 else ''
            online_dot = '🟢 ' if conv.get('is_online') else ''
            text = f'{online_dot}{conv["friend_username"]}{badge}'
            item = QListWidgetItem(text)
            item.setData(Qt.UserRole, conv)
            if unread > 0:
                item.setForeground(QColor('#e94560'))
                item.setFont(QFont('Segoe UI', 12, QFont.Bold))
            self.conversation_list.addItem(item)

    def _refresh_friends(self):
        try:
            data, status = self.api.list_friends()
            if status == 200:
                self._on_friends_updated(data['friends'])
        except Exception:
            pass

    def _refresh_conversations(self):
        try:
            data, status = self.api.get_conversations()
            if status == 200:
                self._on_conversations_updated(data['conversations'])
        except Exception:
            pass

    def _refresh_requests(self):
        try:
            data, status = self.api.get_friend_requests()
            if status == 200:
                self._update_requests_list(data['requests'])
        except Exception:
            pass

    def _update_requests_list(self, requests):
        self.requests_list.clear()
        for req in requests:
            widget = QWidget()
            layout = QHBoxLayout(widget)
            layout.setContentsMargins(4, 4, 4, 4)

            label = QLabel(req['from_username'])
            label.setStyleSheet('background: transparent;')
            layout.addWidget(label)
            layout.addStretch()

            accept_btn = QPushButton('✓')
            accept_btn.setFixedSize(32, 32)
            accept_btn.setStyleSheet('background: #4ecdc4; border-radius: 16px; font-size: 16px;')
            rid = req['id']
            accept_btn.clicked.connect(lambda _checked=False, _rid=rid: self._respond_request(_rid, 'accept'))
            layout.addWidget(accept_btn)

            decline_btn = QPushButton('✗')
            decline_btn.setFixedSize(32, 32)
            decline_btn.setStyleSheet('background: #e94560; border-radius: 16px; font-size: 16px;')
            decline_btn.clicked.connect(lambda _checked=False, _rid=rid: self._respond_request(_rid, 'decline'))
            layout.addWidget(decline_btn)

            item = QListWidgetItem()
            item.setSizeHint(QSize(0, 50))
            item.setFlags(item.flags() & ~Qt.ItemIsSelectable)
            self.requests_list.addItem(item)
            self.requests_list.setItemWidget(item, widget)

    def _respond_request(self, request_id, action):
        try:
            data, status = self.api.respond_friend_request(request_id, action)
            if status == 200:
                self._refresh_requests()
                if action == 'accept':
                    self._refresh_friends()
        except Exception as e:
            QMessageBox.warning(self, 'Error', str(e))

    def _on_add_friend(self):
        username = self.add_friend_input.text().strip()
        if not username:
            return
        try:
            data, status = self.api.send_friend_request(username)
            if status in (200, 201):
                self.add_friend_input.clear()
                QMessageBox.information(self, 'Success', data.get('message', 'Request sent'))
                self._refresh_friends()
            else:
                QMessageBox.warning(self, 'Error', data.get('error', 'Failed'))
        except Exception as e:
            QMessageBox.warning(self, 'Error', str(e))

    def _on_friend_clicked(self, item):
        friend = item.data(Qt.UserRole)
        self._open_chat(friend['user_id'], friend['username'])

    def _on_conversation_clicked(self, item):
        conv = item.data(Qt.UserRole)
        self._open_chat(conv['friend_id'], conv['friend_username'])

    def _open_chat(self, friend_id, friend_name):
        if friend_id not in self.chat_widgets:
            chat = ChatWidget(
                self.api, self.user_id, friend_id, friend_name,
                self.session_mgr, self.message_store, self.key_bundle,
            )
            self.chat_widgets[friend_id] = chat
            self.chat_stack.addWidget(chat)

        self.chat_stack.setCurrentWidget(self.chat_widgets[friend_id])

    def _check_expired_messages(self):
        self.message_store.remove_expired()

    def _on_logout(self):
        self.poll_worker.stop()
        self.poll_thread.quit()
        self.poll_thread.wait(2000)
        try:
            self.api.logout()
        except Exception:
            pass
        self.close()

    def closeEvent(self, event):
        try:
            self.poll_worker.stop()
            self.poll_thread.quit()
            self.poll_thread.wait(2000)
            self.api.logout()
        except Exception:
            pass
        event.accept()


class App(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('SecureChat')
        self.setMinimumSize(500, 600)
        self.api = ApiClient()

        self.login_window = LoginWindow(self.api)
        self.login_window.login_success.connect(self._on_login_success)
        self.setCentralWidget(self.login_window)

    def _on_login_success(self, user_data):
        self.main_window = MainWindow(self.api, user_data)
        self.main_window.show()
        self.close()


def main():
    app = QApplication(sys.argv)
    app.setStyleSheet(STYLE_SHEET)
    window = App()
    window.show()
    sys.exit(app.exec())


if __name__ == '__main__':
    main()
