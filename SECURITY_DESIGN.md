# SecureChat Threat Model and Design (Sections 4–11)

## 4. Threat Model & Assumptions（HbC 伺服器模型與範圍界定）

- **對手與邊界**
- HbC 伺服器：誠實執行協定與存取控制，但可能嘗試窺探明文與金鑰。
- 網路攻擊者：可被動監聽、主動重放/篡改封包。
- 用戶端設備：被信任執行端到端加密；若裝置被完全入侵則不在防護範圍內。

- **信任假設**
- 初次見面（TOFU）：首次取得對方身分金鑰時需假設未被攔改；之後若金鑰改變會在 UI 警示。
  - 參考：client/storage.py 86–100；client/widgets.py 319–325
```python
# client/storage.py (save_contact_key)
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
```
```python
# client/widgets.py (key change warning)
ik = bundle_data['identity_public_key']
if ':' in ik:
    ik = ik.split(':')[1]
key_changed = self.contact_keys.save_contact_key(self.friend_id, ik)
if key_changed:
    QMessageBox.warning(
        self, 'Security Warning',
        f"{self.friend_name}'s identity key has changed!\n"
        'This could indicate a security issue or device change.'
    )
```
- 傳輸層：伺服器預設開啟 TLS，但客戶端目前關閉憑證驗證以便自簽測試。
  - 參考：server/app.py 121–129；client/api_client.py 8, 27
```python
# server/app.py (TLS enabled path)
app = create_app(skip_otp=args.skip_otp)
if args.no_tls:
    print('[WARNING] TLS is DISABLED - connections are not encrypted')
    app.run(host='0.0.0.0', port=5000, debug=False)
else:
    cert_file, key_file = generate_self_signed_cert()
    print('[INFO] Running with TLS enabled')
    app.run(host='0.0.0.0', port=5000, debug=False, ssl_context=(cert_file, key_file))
```
```python
# client/api_client.py (verify flag in requests)
class ApiClient:
    def __init__(self, base_url='https://localhost:5000', verify_ssl=False):
        self.base_url = base_url
        self.token = None
        self.user_id = None
        self.username = None
        self.verify_ssl = verify_ssl

    def _get(self, path, params=None):
        resp = requests.get(
            f'{self.base_url}{path}',
            headers=self._headers(),
            params=params,
            timeout=10,
            verify=self.verify_ssl
        )
        return resp.json(), resp.status_code

    def _post(self, path, data=None):
        resp = requests.post(
            f'{self.base_url}{path}',
            headers=self._headers(),
            json=data,
            timeout=10,
            verify=self.verify_ssl
        )
        return resp.json(), resp.status_code
```

- **不在範圍（Out-of-scope）**
- 終端裝置被植入惡意軟體後竊取密鑰/明文。
- DDoS、側信道、供應鏈攻擊。
- 備份口令若過弱導致離線暴力破解（建議高熵口令）。

## 5. Architecture（信任邊界與資料流）

- **組件與邊界**
- 用戶端：金鑰管理、會話密鑰導出、訊息加解密。
- 伺服器：帳號/好友/訊息中繼、金鑰與備份儲存，不接觸明文。
- 儲存：用戶端 SQLite（會話密鑰、去重）、伺服器 DB（密文、nonce、金鑰素材）。

- **資料流（文字示意）**
```
[Client A] --TLS--> [Server (HbC)] --TLS--> [Client B]
    |                                   ^
    |-- upload keys --------------------|
    |-- get bundle -------------------->|
    |<-- bundle (IK/SPK/OTPK,sig) ------|
    |-- initial E2EE msg (ephemeral) -->|
                                        |-- fetch --> [Client B decrypts]
```

## 6. Protocol Design（會話建立、訊息格式、狀態機、重放處理）

- **會話建立（X25519 + 已簽名 PreKey，類 X3DH）**
- 金鑰上傳：上傳 Ed25519 簽名金鑰與 X25519 身分金鑰、已簽名的 X25519 Signed PreKey、數個一次性預共享金鑰（OTPK）。
```python
# client/crypto_utils.py (extract)
def generate(self, num_otpk=10):
    self.signing_private_key, self.signing_public_key = generate_ed25519_keypair()
    self.identity_private_key, self.identity_public_key = generate_x25519_keypair()
    self.signed_prekey_private, self.signed_prekey_public = generate_x25519_keypair()
    self.signed_prekey_sig = sign_key(self.signing_private_key, self.signed_prekey_public)
    self.one_time_prekeys = []
    for i in range(num_otpk):
        priv, pub = generate_x25519_keypair()
        self.one_time_prekeys.append({'key_id': i, 'private': priv, 'public': pub})

def get_upload_data(self):
    identity_pub_b64 = pub_to_b64(self.signing_public_key) + ':' + pub_to_b64(self.identity_public_key)
    otpks = []
    for otpk in self.one_time_prekeys:
        otpks.append({
            'key_id': otpk['key_id'],
            'public_key': pub_to_b64(otpk['public']),
        })
    return {
        'identity_public_key': identity_pub_b64,
        'signed_prekey_public': pub_to_b64(self.signed_prekey_public),
        'signed_prekey_sig': self.signed_prekey_sig,
        'one_time_prekeys': otpks,
    }
```
- 取用對方束：伺服器在提供 bundle 時會「消耗」一把 OTPK（若存在）。
```python
# server/api/keys.py 46-53
otpk = OneTimePreKey.query.filter_by(user_id=target_user_id, used=False).first()
otpk_data = None
if otpk:
    otpk_data = {'key_id': otpk.key_id, 'public_key': otpk.public_key}
    otpk.used = True
    db.session.commit()
```
```python
# server/api/keys.py (bundle response)
return jsonify({
    'user_id': user.id,
    'username': user.username,
    'identity_public_key': user.identity_public_key,
    'signed_prekey_public': user.signed_prekey_public,
    'signed_prekey_sig': user.signed_prekey_sig,
    'one_time_prekey': otpk_data,
}), 200
```
- 發送端導出共享密鑰與攜帶 ephemeral：
```python
# client/crypto_utils.py (extract)
def init_sender(self, my_keys, recipient_bundle):
    ik_parts = recipient_bundle['identity_public_key'].split(':')
    recipient_signing_pub_b64 = ik_parts[0]
    recipient_ik_pub_b64 = ik_parts[1]
    recipient_spk_pub_b64 = recipient_bundle['signed_prekey_public']
    spk_sig_b64 = recipient_bundle['signed_prekey_sig']

    if not verify_signature(recipient_signing_pub_b64, spk_sig_b64, recipient_spk_pub_b64):
        raise ValueError('Signed prekey signature verification failed')

    recipient_ik_pub = b64_to_x25519_pub(recipient_ik_pub_b64)
    recipient_spk_pub = b64_to_x25519_pub(recipient_spk_pub_b64)

    ephemeral_private, ephemeral_public = generate_x25519_keypair()

    dh1 = x25519_derive_shared(my_keys.identity_private_key, recipient_spk_pub)
    dh2 = x25519_derive_shared(ephemeral_private, recipient_ik_pub)
    dh3 = x25519_derive_shared(ephemeral_private, recipient_spk_pub)

    shared_secrets = [dh1, dh2, dh3]

    otpk = recipient_bundle.get('one_time_prekey')
    if otpk:
        otpk_pub = b64_to_x25519_pub(otpk['public_key'])
        dh4 = x25519_derive_shared(ephemeral_private, otpk_pub)
        shared_secrets.append(dh4)

    self.shared_key = kdf_derive(shared_secrets)
    return pub_to_b64(ephemeral_public)
```
- 接收端重建共享密鑰：
```python
# client/crypto_utils.py (extract)
def init_receiver(self, my_keys, sender_ik_pub_b64_full, ephemeral_pub_b64, otpk_key_id=None):
    ik_parts = sender_ik_pub_b64_full.split(':')
    sender_ik_pub_b64 = ik_parts[1]

    sender_ik_pub = b64_to_x25519_pub(sender_ik_pub_b64)
    ephemeral_pub = b64_to_x25519_pub(ephemeral_pub_b64)

    dh1 = x25519_derive_shared(my_keys.signed_prekey_private, sender_ik_pub)
    dh2 = x25519_derive_shared(my_keys.identity_private_key, ephemeral_pub)
    dh3 = x25519_derive_shared(my_keys.signed_prekey_private, ephemeral_pub)

    shared_secrets = [dh1, dh2, dh3]

    if otpk_key_id is not None:
        for otpk in my_keys.one_time_prekeys:
            if otpk['key_id'] == otpk_key_id:
                dh4 = x25519_derive_shared(otpk['private'], ephemeral_pub)
                shared_secrets.append(dh4)
                break

    self.shared_key = kdf_derive(shared_secrets)
```

- **訊息格式與 AEAD 綁定**
- 加密：AES-GCM 256、隨機 96-bit nonce、HKDF-SHA256 導出 32 bytes、可選 AAD 綁定雙方身分與 TTL。
```python
# client/crypto_utils.py 103-114
nonce = os.urandom(12)
ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
```
```python
# client/widgets.py 352-357（AAD 綁定）
ad = json.dumps({'sender_id': int(self.my_user_id),
                 'receiver_id': int(self.friend_id),
                 'ttl': self_destruct_seconds}, sort_keys=True)
ciphertext, nonce = cipher.encrypt(text, ad)
```
- 初始訊息附帶 ephemeral_key JSON：
```python
# client/widgets.py 332-338
initial_info = json.dumps({
  'sender_ik': ik_data,
  'ephemeral_key': ephemeral_pub_b64,
  'otpk_key_id': bundle_data['one_time_prekey']['key_id'] if bundle_data.get('one_time_prekey') else None,
})
```

- **狀態機（簡述）**
- 無會話 → 取 bundle → 驗簽 SPK → 雙方導出 shared_key → 發送 initial → 之後 normal 訊息重用此 shared_key。

- **重放處理**
- 密碼學層：AES-GCM 可偵測內容/AD 篡改，但不自帶反重放。
- 應用層：客戶端以 message_id 去重（SQLite seen_messages 表）。
```python
# client/storage.py 198-217
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
```

## 7. Cryptographic Choices & Rationale

- **金鑰交換**：X25519（輕量高安全，廣泛部署）。
- **身分簽名**：Ed25519（快速、免參數）。
- **密碼模式**：AES-256-GCM（AEAD，機密性與完整性）。
- **KDF**：HKDF-SHA256（client/crypto_utils.py 92–100）。
```python
# client/crypto_utils.py (kdf_derive)
def kdf_derive(shared_secrets, info=b'SecureChat'):
    ikm = b''.join(shared_secrets)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'\x00' * 32,
        info=info,
    )
    return hkdf.derive(ikm)
```
- **備份衍生**：PBKDF2-HMAC-SHA256、600,000 次迭代（client/crypto_utils.py 127–137）。
```python
# client/crypto_utils.py (derive_key_from_passphrase)
def derive_key_from_passphrase(passphrase, salt=None):
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600000,
    )
    key = kdf.derive(passphrase.encode('utf-8'))
    return key, salt
```
```python
# client/crypto_utils.py (backup helpers)
def encrypt_backup(plaintext_json, passphrase):
    key, salt = derive_key_from_passphrase(passphrase)
    ciphertext_b64, nonce_b64 = aes_encrypt(key, plaintext_json)
    salt_b64 = base64.b64encode(salt).decode('utf-8')
    return ciphertext_b64, nonce_b64, salt_b64

def decrypt_backup(ciphertext_b64, nonce_b64, salt_b64, passphrase):
    salt = base64.b64decode(salt_b64)
    key, _ = derive_key_from_passphrase(passphrase, salt)
    return aes_decrypt(key, ciphertext_b64, nonce_b64)
```
```python
# server/api/keys.py (backup endpoints excerpt)
@keys_bp.route('/backup', methods=['POST'])
@jwt_required()
def upload_backup():
    user_id = int(get_jwt_identity())
    data = request.get_json()
    encrypted_data = data.get('encrypted_data')
    nonce = data.get('nonce')
    salt = data.get('salt')
    if not encrypted_data or not nonce or not salt:
        return jsonify({'error': 'Missing backup fields'}), 400
    backup = KeyBackup.query.filter_by(user_id=user_id).first()
    if backup:
        backup.encrypted_data = encrypted_data
        backup.nonce = nonce
        backup.salt = salt
        backup.updated_at = datetime.utcnow()
    else:
        backup = KeyBackup(user_id=user_id, encrypted_data=encrypted_data, nonce=nonce, salt=salt)
        db.session.add(backup)
    db.session.commit()
    return jsonify({'message': 'Backup saved'}), 200

@keys_bp.route('/backup', methods=['GET'])
@jwt_required()
def download_backup():
    user_id = int(get_jwt_identity())
    backup = KeyBackup.query.filter_by(user_id=user_id).first()
    if not backup:
        return jsonify({'error': 'No backup found'}), 404
    return jsonify({
        'encrypted_data': backup.encrypted_data,
        'nonce': backup.nonce,
        'salt': backup.salt,
        'updated_at': backup.updated_at.isoformat(),
    }), 200
```
- **伺服器密碼**：Argon2（server/api/auth.py 8–9）。
- **2FA**：TOTP（server/api/auth.py 4，102–105）。
```python
# server/api/auth.py (login excerpt: Argon2 + TOTP)
user = User.query.filter_by(username=username).first()
if not user:
    return jsonify({'error': 'Invalid credentials'}), 401

try:
    ph.verify(user.password_hash, password)
except VerifyMismatchError:
    return jsonify({'error': 'Invalid credentials'}), 401

if not skip_otp:
    totp = pyotp.TOTP(user.otp_secret)
    if not totp.verify(otp_code, valid_window=1):
        return jsonify({'error': 'Invalid OTP code'}), 401
```
- **TLS**：預設啟用自簽（server/app.py 121–129）。
- **套件版本（server/requirements.txt）**：
```text
Flask==3.0.0
Flask-SQLAlchemy==3.1.1
Flask-JWT-Extended==4.6.0
pyotp==2.9.0
qrcode==7.4.2
argon2-cffi==23.1.0
cryptography==41.0.7
Pillow==10.2.0
```

## 8. Security Analysis

- **為何伺服器學不到明文**
- 明文只在客戶端加/解密；伺服器僅儲存 ciphertext、nonce、ephemeral_key、message_type 等。
  - 參考：server/api/messages.py 49–66, 95–111
```python
# server/api/messages.py (send_message)
@messages_bp.route('/send', methods=['POST'])
@jwt_required()
def send_message():
    user_id = int(get_jwt_identity())
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid request'}), 400

    receiver_id = data.get('receiver_id')
    ciphertext = data.get('ciphertext')
    nonce = data.get('nonce')
    ephemeral_key = data.get('ephemeral_key')
    message_type = data.get('message_type', 'normal')
    self_destruct_seconds = data.get('self_destruct_seconds')

    if not receiver_id or not ciphertext or not nonce:
        return jsonify({'error': 'Missing required fields'}), 400

    if not isinstance(receiver_id, int) or receiver_id <= 0:
        return jsonify({'error': 'Invalid receiver_id'}), 400

    if len(ciphertext) > MAX_MESSAGE_SIZE:
        return jsonify({'error': 'Message too large'}), 400

    if message_type not in ('normal', 'initial'):
        return jsonify({'error': 'Invalid message type'}), 400

    if self_destruct_seconds is not None:
        if not isinstance(self_destruct_seconds, int) or self_destruct_seconds < 1 or self_destruct_seconds > 604800:
            return jsonify({'error': 'Invalid self_destruct_seconds (1-604800)'}), 400

    friendship = Friendship.query.filter_by(user_id=user_id, friend_id=receiver_id).first()
    if not friendship:
        return jsonify({'error': 'Not friends with this user'}), 403

    msg = Message(
        sender_id=user_id,
        receiver_id=receiver_id,
        ciphertext=ciphertext,
        nonce=nonce,
        ephemeral_key=ephemeral_key,
        message_type=message_type,
        self_destruct_seconds=self_destruct_seconds,
        status='sent',
    )
    db.session.add(msg)
    db.session.commit()

    return jsonify({
        'message_id': msg.id,
        'status': 'sent',
        'created_at': msg.created_at.isoformat(),
    }), 201
```
```python
# server/api/messages.py (fetch_messages excerpt)
@messages_bp.route('/fetch', methods=['GET'])
@jwt_required()
def fetch_messages():
    user_id = int(get_jwt_identity())
    user = User.query.get(user_id)
    if user:
        user.is_online = True
        user.last_seen = datetime.utcnow()
        db.session.commit()

    now = datetime.utcnow()
    expired = Message.query.filter(
        Message.self_destruct_seconds.isnot(None),
        Message.delivered_at.isnot(None),
    ).all()
    for msg in expired:
        expire_time = msg.delivered_at + timedelta(seconds=msg.self_destruct_seconds)
        if now > expire_time:
            db.session.delete(msg)
    db.session.commit()

    messages = Message.query.filter_by(receiver_id=user_id, status='sent').order_by(
        Message.created_at.asc()
    ).all()

    result = []
    for msg in messages:
        msg.status = 'delivered'
        msg.delivered_at = datetime.utcnow()
        result.append({
            'message_id': msg.id,
            'sender_id': msg.sender_id,
            'ciphertext': msg.ciphertext,
            'nonce': msg.nonce,
            'ephemeral_key': msg.ephemeral_key,
            'message_type': msg.message_type,
            'self_destruct_seconds': msg.self_destruct_seconds,
            'created_at': msg.created_at.isoformat(),
        })

    db.session.commit()
    return jsonify({'messages': result}), 200
```
- 共享密鑰由雙方本地以多路 X25519 DH + HKDF 導出，伺服器無法計算。

- **伺服器/旁觀者可見中介資料**
- 雙方帳號 ID、好友關係、線上狀態與時間戳、訊息長度、TTL、自毀時間、傳遞與已讀狀態。
- 初始訊息的發送者身分金鑰與發送端 ephemeral 公鑰（作為 ephemeral_key 載荷的一部分）。

- **限制與取捨**
- TOFU：首次取得對方身分金鑰可能被竄改；僅提供「金鑰變更」警示（建議加入指紋比對）。
  - 指紋：client/crypto_utils.py 81–85
```python
# client/crypto_utils.py (generate_fingerprint)
def generate_fingerprint(identity_public_key_b64):
    import hashlib
    key_bytes = base64.b64decode(identity_public_key_b64.split(':')[-1])
    digest = hashlib.sha256(key_bytes).hexdigest().upper()
    return ' '.join([digest[i:i+4] for i in range(0, 32, 4)])
```
- 無雙向 ratchet：後續訊息共用同一把 shared_key，缺乏訊息級 PFS 與未來保密。
- 反重放主要靠應用層 message_id 去重，缺少密碼學序號/重放視窗。
- 客戶端目前關閉 TLS 憑證驗證，登入階段易受 MITM；建議啟用驗證或植入受信根憑證。

## 9. Testing & Evaluation

- **示範：金鑰與會話建立、加解密關鍵路徑**
- 產生與上傳金鑰：KeyBundle.generate() → get_upload_data() → ApiClient.upload_keys()
  - 參考：client/crypto_utils.py 164–187；client/api_client.py 63–65
```python
# client/api_client.py (upload_keys)
def upload_keys(self, key_data):
    return self._post('/api/keys/upload', key_data)
```
- 取 bundle 與會話導出：ApiClient.get_key_bundle() → SessionCipher.init_sender()/init_receiver()
  - 參考：client/crypto_utils.py 263–314；client/widgets.py 326–338；server/api/keys.py 36–60
```python
# client/api_client.py (get_key_bundle)
def get_key_bundle(self, target_user_id):
    return self._get(f'/api/keys/bundle/{target_user_id}')
```
```python
# client/api_client.py (backup helpers)
def upload_backup(self, encrypted_data, nonce, salt):
    return self._post('/api/keys/backup', {
        'encrypted_data': encrypted_data,
        'nonce': nonce,
        'salt': salt,
    })

def download_backup(self):
    return self._get('/api/keys/backup')
```
- 加密傳送與接收解密（附 AAD）：
  - 參考：client/widgets.py 352–369；client/main.py 370–410；server/api/messages.py 14–67, 69–111
```python
# client/api_client.py (send_message)
def send_message(self, receiver_id, ciphertext, nonce, ephemeral_key=None,
                 message_type='normal', self_destruct_seconds=None):
    data = {
        'receiver_id': receiver_id,
        'ciphertext': ciphertext,
        'nonce': nonce,
        'ephemeral_key': ephemeral_key,
        'message_type': message_type,
        'self_destruct_seconds': self_destruct_seconds,
    }
    return self._post('/api/messages/send', data)
```
```python
# client/widgets.py (_send_message excerpt)
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
        ad = json.dumps({
            'sender_id': int(self.my_user_id),
            'receiver_id': int(self.friend_id),
            'ttl': self_destruct_seconds,
        }, sort_keys=True)
        ciphertext, nonce = cipher.encrypt(text, ad)
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
        # ... update UI and local store ...
    finally:
        self.send_btn.setEnabled(True)
```
```python
# client/main.py (_decrypt_message)
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
        self.contact_keys.save_contact_key(sender_id, sender_ik)
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
                    self.contact_keys.save_contact_key(sender_id, ik)
            except Exception:
                pass
        return cipher.decrypt(msg['ciphertext'], msg['nonce'], ad)
```

- **至少兩個安全測試案例**
- 篡改偵測（完整性/AAD 綁定）
  - 步驟：加密後任意改動 ciphertext 或 associated_data，再嘗試解密。
  - 預期：AESGCM.decrypt() 丟出例外，解密失敗（client/crypto_utils.py 117–124）。
```python
# client/crypto_utils.py (aes_decrypt)
def aes_decrypt(key, ciphertext_b64, nonce_b64, associated_data=None):
    aesgcm = AESGCM(key)
    ciphertext = base64.b64decode(ciphertext_b64)
    nonce = base64.b64decode(nonce_b64)
    if associated_data and isinstance(associated_data, str):
        associated_data = associated_data.encode('utf-8')
    plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data)
    return plaintext.decode('utf-8')
```
- 已簽名 PreKey 驗證
  - 步驟：取得對方 bundle 後，手動竄改 signed_prekey_sig 再呼叫 SessionCipher.init_sender()。
  - 預期：拋出 ValueError('Signed prekey signature verification failed')（client/crypto_utils.py 270–272）。
- （加值）重放去重
  - 同一 message_id 重送到客戶端，應被 is_duplicate() 濾除（client/storage.py 198–206）。

## 10. Future Works

- 導入 Double Ratchet（訊息級前向/未來保密、雙向更新）。
- 金鑰指紋 UI 與離線驗證流程（掃碼/比對短認證字串）。
- 啟用 TLS 憑證驗證與憑證釘選；生產避免 verify_ssl=False。
- 加入每訊息序號與接收端反重放視窗（drop 舊 nonce/序號）。
- 金鑰透明度/信任目錄（防伺服器供應惡意身分金鑰）。
- 多裝置與金鑰遷移、訊息同步策略。
- 中繼隱私：最小化伺服器可見中介資料（如 Sealed Sender 類型設計）。

## 11. References

- Signal X3DH（會話建立）與 Double Ratchet（訊息層 ratchet）
- RFC 5869（HKDF），NIST SP 800-38D（AES-GCM）
- Ed25519/X25519（Curve25519 家族）與 libsodium/cryptography 文檔
- Argon2 規範，RFC 6238（TOTP）
- Flask-JWT-Extended 文檔
