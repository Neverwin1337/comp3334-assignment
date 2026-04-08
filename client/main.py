import sys
import os
import json
import base64
import time
import argparse
from datetime import datetime

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QListWidget, QListWidgetItem,
    QStackedWidget, QMessageBox, QFrame, QDialog, QTabWidget,
)
from PySide6.QtCore import Qt, QTimer, QThread, QSize
from PySide6.QtGui import QFont, QColor

from api_client import ApiClient
from crypto_utils import KeyBundle, SessionCipher, encrypt_backup, decrypt_backup, generate_fingerprint
from styles import STYLE_SHEET
from storage import SessionManager, MessageStore, ContactKeyStore, DATA_DIR
from workers import PollingWorker
from widgets import LoginWindow, ChatWidget


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
        self.contact_keys = ContactKeyStore(self.username)
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
        self.friends_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.friends_list.customContextMenuRequested.connect(self._on_friend_context_menu)
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
        self.poll_worker.sent_status_updated.connect(self._on_sent_status_updated)
        self.poll_thread.started.connect(self.poll_worker.poll)
        self.poll_thread.start()

    def _on_new_messages(self, messages):
        ack_ids = []
        for msg in messages:
            msg_id = msg['message_id']
            ciphertext = msg.get('ciphertext', '')

            if self.message_store.is_duplicate(msg_id):
                ack_ids.append(msg_id)
                continue

            if self.message_store.is_duplicate_ciphertext(ciphertext):
                ack_ids.append(msg_id)
                continue

            sender_id = msg['sender_id']
            try:
                plaintext = self._decrypt_message(msg)
                ts = datetime.fromisoformat(msg['created_at']).strftime('%H:%M')
                sd = msg.get('self_destruct_seconds')

                self.message_store.mark_seen(msg_id, ciphertext)

                if sender_id in self.chat_widgets:
                    self.chat_widgets[sender_id].receive_message(plaintext, ts, sd, msg_id)
                else:
                    now = time.time()
                    msg_data = {
                        'sender_id': sender_id,
                        'text': plaintext,
                        'timestamp': ts,
                        'status': 'delivered',
                        'message_id': msg_id,
                        'self_destruct_seconds': sd,
                    }
                    if sd:
                        msg_data['expire_at'] = now + sd
                    self.message_store.add_message(sender_id, msg_data)

                ack_ids.append(msg_id)
            except Exception as e:
                import traceback
                print(f'Decrypt error for message {msg_id}: {e}')
                traceback.print_exc()

        if ack_ids:
            try:
                self.api.ack_messages(ack_ids)
            except Exception:
                pass

        self._refresh_conversations()

    def _decrypt_message(self, msg):
        sender_id = msg['sender_id']

        ad = json.dumps({
            'sender_id': int(sender_id),
            'receiver_id': int(self.user_id),
            'ttl': msg.get('self_destruct_seconds'),
        }, sort_keys=True)

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
            sender_ik = info['sender_ik']
            if ':' in sender_ik:
                sender_ik = sender_ik.split(':')[1]
            key_changed = self.contact_keys.save_contact_key(sender_id, sender_ik)
            if key_changed:
                self._show_key_change_warning(sender_id)
            return cipher.decrypt(msg['ciphertext'], msg['nonce'], ad)
        else:
            cipher = self.session_mgr.get_session(sender_id)
            if not cipher:
                raise Exception('No session found for this sender')
            if not self.contact_keys.get_contact(sender_id):
                try:
                    bundle_data, status = self.api.get_key_bundle(sender_id)
                    if status == 200:
                        ik = bundle_data['identity_public_key']
                        if ':' in ik:
                            ik = ik.split(':')[1]
                        key_changed = self.contact_keys.save_contact_key(sender_id, ik)
                        if key_changed:
                            self._show_key_change_warning(sender_id)
                except Exception:
                    pass
            return cipher.decrypt(msg['ciphertext'], msg['nonce'], ad)

    def _show_key_change_warning(self, user_id):
        friend_name = f'User {user_id}'
        for f in getattr(self, '_friends_data', []):
            if f.get('id') == user_id:
                friend_name = f.get('username', friend_name)
                break
        QMessageBox.warning(
            self, 'Security Warning',
            f'{friend_name}\'s identity key has changed!\n\n'
            'This could indicate:\n'
            '• The contact reinstalled the app\n'
            '• The contact is using a new device\n'
            '• A potential security threat (man-in-the-middle attack)\n\n'
            'Please verify this change with your contact through another channel.'
        )

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

    def _on_sent_status_updated(self, statuses):
        changed_friends = set()
        for s in statuses:
            mid = s['message_id']
            new_status = s['status']
            for friend_id, msgs in self.message_store.messages.items():
                for msg in msgs:
                    if msg.get('message_id') == mid and msg.get('status') != new_status:
                        self.message_store.update_message_status(mid, new_status)
                        changed_friends.add(int(friend_id))
                        break
        for fid in changed_friends:
            if fid in self.chat_widgets:
                self.chat_widgets[fid].refresh_messages()

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

    def _on_friend_context_menu(self, pos):
        from PySide6.QtWidgets import QMenu
        item = self.friends_list.itemAt(pos)
        if not item:
            return
        friend = item.data(Qt.UserRole)
        if not friend:
            return

        menu = QMenu(self)
        remove_action = menu.addAction('Remove Friend')
        block_action = menu.addAction('Block User')

        action = menu.exec(self.friends_list.mapToGlobal(pos))
        if action == remove_action:
            self._remove_friend(friend['user_id'], friend['username'])
        elif action == block_action:
            self._block_user(friend['user_id'], friend['username'])

    def _remove_friend(self, friend_id, username):
        reply = QMessageBox.question(
            self, 'Remove Friend',
            f'Remove {username} from friends?',
            QMessageBox.Yes | QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            try:
                data, status = self.api.remove_friend(friend_id)
                if status == 200:
                    self._refresh_friends()
                    self._refresh_conversations()
                else:
                    QMessageBox.warning(self, 'Error', data.get('error', 'Failed'))
            except Exception as e:
                QMessageBox.warning(self, 'Error', str(e))

    def _block_user(self, user_id, username):
        reply = QMessageBox.question(
            self, 'Block User',
            f'Block {username}? This will also remove them from friends.',
            QMessageBox.Yes | QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            try:
                data, status = self.api.block_user(user_id)
                if status == 200:
                    self._refresh_friends()
                    self._refresh_conversations()
                    QMessageBox.information(self, 'Blocked', f'{username} has been blocked.')
                else:
                    QMessageBox.warning(self, 'Error', data.get('error', 'Failed'))
            except Exception as e:
                QMessageBox.warning(self, 'Error', str(e))

    def _on_conversation_clicked(self, item):
        conv = item.data(Qt.UserRole)
        self._open_chat(conv['friend_id'], conv['friend_username'])

    def _open_chat(self, friend_id, friend_name):
        if friend_id not in self.chat_widgets:
            chat = ChatWidget(
                self.api, self.user_id, friend_id, friend_name,
                self.session_mgr, self.message_store, self.key_bundle,
                self.contact_keys,
            )
            self.chat_widgets[friend_id] = chat
            self.chat_stack.addWidget(chat)

        self.chat_stack.setCurrentWidget(self.chat_widgets[friend_id])

    def _check_expired_messages(self):
        old_counts = {k: len(v) for k, v in self.message_store.messages.items()}
        self.message_store.remove_expired()
        for friend_id, old_count in old_counts.items():
            new_count = len(self.message_store.messages.get(friend_id, []))
            if new_count < old_count:
                fid = int(friend_id)
                if fid in self.chat_widgets:
                    self.chat_widgets[fid].refresh_messages()

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
    def __init__(self, skip_otp=False):
        super().__init__()
        self.setWindowTitle('SecureChat')
        self.setMinimumSize(500, 600)
        self.api = ApiClient()

        self.login_window = LoginWindow(self.api, skip_otp=skip_otp)
        self.login_window.login_success.connect(self._on_login_success)
        self.setCentralWidget(self.login_window)

    def _on_login_success(self, user_data):
        self.main_window = MainWindow(self.api, user_data)
        self.main_window.show()
        self.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--skip-otp', action='store_true', help='Skip OTP verification for login')
    args = parser.parse_args()

    if args.skip_otp:
        print('[WARNING] OTP verification is DISABLED')

    app = QApplication(sys.argv)
    app.setStyleSheet(STYLE_SHEET)
    window = App(skip_otp=args.skip_otp)
    window.show()
    sys.exit(app.exec())


if __name__ == '__main__':
    main()
