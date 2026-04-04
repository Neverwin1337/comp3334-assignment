import os
import sqlite3
import time
import base64

DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')
os.makedirs(DATA_DIR, exist_ok=True)


def get_db_path(username):
    return os.path.join(DATA_DIR, f'{username}.db')


def init_db(username):
    db_path = get_db_path(username)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    c.execute('''
        CREATE TABLE IF NOT EXISTS contacts (
            user_id INTEGER PRIMARY KEY,
            identity_key TEXT NOT NULL,
            verified INTEGER DEFAULT 0,
            key_changed INTEGER DEFAULT 0
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            friend_id INTEGER PRIMARY KEY,
            shared_key TEXT NOT NULL
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            friend_id INTEGER NOT NULL,
            sender_id INTEGER,
            text TEXT,
            timestamp TEXT,
            status TEXT,
            message_id INTEGER,
            self_destruct_seconds INTEGER,
            expire_at REAL
        )
    ''')
    c.execute('CREATE INDEX IF NOT EXISTS idx_messages_friend ON messages(friend_id)')

    c.execute('''
        CREATE TABLE IF NOT EXISTS seen_messages (
            message_id INTEGER PRIMARY KEY
        )
    ''')

    conn.commit()
    conn.close()


class ContactKeyStore:
    def __init__(self, username):
        self.username = username
        self.db_path = get_db_path(username)
        init_db(username)

    def _conn(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def get_contact(self, user_id):
        conn = self._conn()
        c = conn.cursor()
        c.execute('SELECT * FROM contacts WHERE user_id = ?', (int(user_id),))
        row = c.fetchone()
        conn.close()
        if row:
            return {
                'identity_key': row['identity_key'],
                'verified': bool(row['verified']),
                'key_changed': bool(row['key_changed']),
            }
        return None

    def save_contact_key(self, user_id, identity_key, verified=False):
        user_id = int(user_id)
        existing = self.get_contact(user_id)
        key_changed = bool(existing and existing.get('identity_key') != identity_key)

        conn = self._conn()
        c = conn.cursor()
        c.execute('''
            INSERT OR REPLACE INTO contacts (user_id, identity_key, verified, key_changed)
            VALUES (?, ?, ?, ?)
        ''', (user_id, identity_key, 0 if key_changed else int(verified), int(key_changed)))
        conn.commit()
        conn.close()
        return key_changed

    def mark_verified(self, user_id, verified=True):
        conn = self._conn()
        c = conn.cursor()
        c.execute('UPDATE contacts SET verified = ?, key_changed = 0 WHERE user_id = ?',
                  (int(verified), int(user_id)))
        conn.commit()
        conn.close()

    def is_verified(self, user_id):
        contact = self.get_contact(user_id)
        return contact.get('verified', False) if contact else False

    def has_key_changed(self, user_id):
        contact = self.get_contact(user_id)
        return contact.get('key_changed', False) if contact else False


class SessionManager:
    def __init__(self, username):
        self.username = username
        self.db_path = get_db_path(username)
        init_db(username)

    def _conn(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def has_session(self, friend_id):
        conn = self._conn()
        c = conn.cursor()
        c.execute('SELECT 1 FROM sessions WHERE friend_id = ?', (int(friend_id),))
        result = c.fetchone() is not None
        conn.close()
        return result

    def save_session(self, friend_id, shared_key_b64):
        conn = self._conn()
        c = conn.cursor()
        c.execute('INSERT OR REPLACE INTO sessions (friend_id, shared_key) VALUES (?, ?)',
                  (int(friend_id), shared_key_b64))
        conn.commit()
        conn.close()

    def get_session(self, friend_id):
        from crypto_utils import SessionCipher
        conn = self._conn()
        c = conn.cursor()
        c.execute('SELECT shared_key FROM sessions WHERE friend_id = ?', (int(friend_id),))
        row = c.fetchone()
        conn.close()
        if row:
            cipher = SessionCipher()
            cipher.shared_key = base64.b64decode(row['shared_key'])
            return cipher
        return None


class MessageStore:
    def __init__(self, username):
        self.username = username
        self.db_path = get_db_path(username)
        init_db(username)
        self.messages = {}
        self._load_messages()

    def _conn(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _load_messages(self):
        conn = self._conn()
        c = conn.cursor()
        c.execute('SELECT * FROM messages ORDER BY id ASC')
        rows = c.fetchall()
        conn.close()

        self.messages = {}
        for row in rows:
            fid = str(row['friend_id'])
            if fid not in self.messages:
                self.messages[fid] = []
            self.messages[fid].append({
                'id': row['id'],
                'sender_id': row['sender_id'],
                'text': row['text'],
                'timestamp': row['timestamp'],
                'status': row['status'],
                'message_id': row['message_id'],
                'self_destruct_seconds': row['self_destruct_seconds'],
                'expire_at': row['expire_at'],
            })

    def _save(self):
        pass

    def is_duplicate(self, message_id):
        if message_id is None:
            return False
        conn = self._conn()
        c = conn.cursor()
        c.execute('SELECT 1 FROM seen_messages WHERE message_id = ?', (int(message_id),))
        result = c.fetchone() is not None
        conn.close()
        return result

    def mark_seen(self, message_id):
        if message_id is None:
            return
        conn = self._conn()
        c = conn.cursor()
        c.execute('INSERT OR IGNORE INTO seen_messages (message_id) VALUES (?)', (int(message_id),))
        c.execute('DELETE FROM seen_messages WHERE message_id NOT IN (SELECT message_id FROM seen_messages ORDER BY message_id DESC LIMIT 10000)')
        conn.commit()
        conn.close()

    def add_message(self, friend_id, msg):
        conn = self._conn()
        c = conn.cursor()
        sender_id = msg.get('sender_id')
        msg_id = msg.get('message_id')
        sd_seconds = msg.get('self_destruct_seconds')
        c.execute('''
            INSERT INTO messages (friend_id, sender_id, text, timestamp, status, message_id, self_destruct_seconds, expire_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            int(friend_id) if friend_id is not None else 0,
            int(sender_id) if sender_id is not None else None,
            msg.get('text') or '',
            msg.get('timestamp'),
            msg.get('status'),
            int(msg_id) if msg_id is not None else None,
            int(sd_seconds) if sd_seconds is not None else None,
            msg.get('expire_at'),
        ))
        conn.commit()
        conn.close()

        fid = str(friend_id)
        if fid not in self.messages:
            self.messages[fid] = []
        self.messages[fid].append(msg)

    def get_messages(self, friend_id):
        return self.messages.get(str(friend_id), [])

    def remove_expired(self):
        now = time.time()
        conn = self._conn()
        c = conn.cursor()
        c.execute('DELETE FROM messages WHERE expire_at IS NOT NULL AND expire_at <= ?', (now,))
        deleted = c.rowcount
        conn.commit()
        conn.close()

        if deleted > 0:
            self._load_messages()

    def update_message_status(self, message_id, status):
        if message_id is None:
            return
        conn = self._conn()
        c = conn.cursor()
        c.execute('UPDATE messages SET status = ? WHERE message_id = ?', (status, int(message_id)))
        conn.commit()
        conn.close()

        for fid, msgs in self.messages.items():
            for msg in msgs:
                if msg.get('message_id') == message_id:
                    msg['status'] = status
                    return
