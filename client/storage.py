import os
import json
import time
import base64

DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')
os.makedirs(DATA_DIR, exist_ok=True)


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
        from crypto_utils import SessionCipher
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
