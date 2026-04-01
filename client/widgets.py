import json
import time
import base64
from datetime import datetime

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton,
    QFrame, QScrollArea, QSpinBox, QCheckBox, QMessageBox, QDialog,
)
from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QPixmap, QFont

from crypto_utils import SessionCipher


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
