# SecureChat Threat Model and Design (Sections 4–11)

## 4. Threat Model & Assumptions（HbC 伺服器模型與範圍界定）

- **對手與邊界**
- HbC 伺服器：誠實執行協定與存取控制，但可能嘗試窺探明文與金鑰。
- 網路攻擊者：可被動監聽、主動重放/篡改封包。
- 用戶端設備：被信任執行端到端加密；若裝置被完全入侵則不在防護範圍內。

- **信任假設**
- 初次見面（TOFU）：首次取得對方身分金鑰時需假設未被攔改；之後若金鑰改變會在 UI 警示。
  - 參考：client/storage.py 86–100；client/widgets.py 319–325
- 傳輸層：伺服器預設開啟 TLS，但客戶端目前關閉憑證驗證以便自簽測試。
  - 參考：server/app.py 121–129；client/api_client.py 8, 27

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
# client/crypto_utils.py 164-176, 183-187
self.signed_prekey_sig = sign_key(self.signing_private_key, self.signed_prekey_public)
return {
    'identity_public_key': pub_to_b64(self.signing_public_key) + ':' + pub_to_b64(self.identity_public_key),
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
- 發送端導出共享密鑰與攜帶 ephemeral：
```python
# client/crypto_utils.py 270-291
if not verify_signature(recipient_signing_pub_b64, spk_sig_b64, recipient_spk_pub_b64):
    raise ValueError('Signed prekey signature verification failed')
recipient_ik_pub = b64_to_x25519_pub(recipient_ik_pub_b64)
recipient_spk_pub = b64_to_x25519_pub(recipient_spk_pub_b64)
...
dh1 = x25519_derive_shared(my_keys.identity_private_key, recipient_spk_pub)
dh2 = x25519_derive_shared(ephemeral_private, recipient_ik_pub)
dh3 = x25519_derive_shared(ephemeral_private, recipient_spk_pub)
if otpk: dh4 = x25519_derive_shared(ephemeral_private, otpk_pub)
self.shared_key = kdf_derive(shared_secrets)
```
- 接收端重建共享密鑰：
```python
# client/crypto_utils.py 300-314
dh1 = x25519_derive_shared(my_keys.signed_prekey_private, sender_ik_pub)
dh2 = x25519_derive_shared(my_keys.identity_private_key, ephemeral_pub)
dh3 = x25519_derive_shared(my_keys.signed_prekey_private, ephemeral_pub)
if otpk_key_id: ...
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
def is_duplicate(self, message_id): ...
def mark_seen(self, message_id): ...
```

## 7. Cryptographic Choices & Rationale

- **金鑰交換**：X25519（輕量高安全，廣泛部署）。
- **身分簽名**：Ed25519（快速、免參數）。
- **密碼模式**：AES-256-GCM（AEAD，機密性與完整性）。
- **KDF**：HKDF-SHA256（client/crypto_utils.py 92–100）。
- **備份衍生**：PBKDF2-HMAC-SHA256、600,000 次迭代（client/crypto_utils.py 127–137）。
- **伺服器密碼**：Argon2（server/api/auth.py 8–9）。
- **2FA**：TOTP（server/api/auth.py 4，102–105）。
- **TLS**：預設啟用自簽（server/app.py 121–129）。
- **套件版本（server/requirements.txt）**：cryptography==41.0.7、Flask-JWT-Extended==4.6.0、argon2-cffi==23.1.0、pyotp==2.9.0。

## 8. Security Analysis

- **為何伺服器學不到明文**
- 明文只在客戶端加/解密；伺服器僅儲存 ciphertext、nonce、ephemeral_key、message_type 等。
  - 參考：server/api/messages.py 49–66, 95–111
- 共享密鑰由雙方本地以多路 X25519 DH + HKDF 導出，伺服器無法計算。

- **伺服器/旁觀者可見中介資料**
- 雙方帳號 ID、好友關係、線上狀態與時間戳、訊息長度、TTL、自毀時間、傳遞與已讀狀態。
- 初始訊息的發送者身分金鑰與發送端 ephemeral 公鑰（作為 ephemeral_key 載荷的一部分）。

- **限制與取捨**
- TOFU：首次取得對方身分金鑰可能被竄改；僅提供「金鑰變更」警示（建議加入指紋比對）。
  - 指紋：client/crypto_utils.py 81–85
- 無雙向 ratchet：後續訊息共用同一把 shared_key，缺乏訊息級 PFS 與未來保密。
- 反重放主要靠應用層 message_id 去重，缺少密碼學序號/重放視窗。
- 客戶端目前關閉 TLS 憑證驗證，登入階段易受 MITM；建議啟用驗證或植入受信根憑證。

## 9. Testing & Evaluation

- **示範：金鑰與會話建立、加解密關鍵路徑**
- 產生與上傳金鑰：KeyBundle.generate() → get_upload_data() → ApiClient.upload_keys()
  - 參考：client/crypto_utils.py 164–187；client/api_client.py 63–65
- 取 bundle 與會話導出：ApiClient.get_key_bundle() → SessionCipher.init_sender()/init_receiver()
  - 參考：client/crypto_utils.py 263–314；client/widgets.py 326–338；server/api/keys.py 36–60
- 加密傳送與接收解密（附 AAD）：
  - 參考：client/widgets.py 352–369；client/main.py 370–410；server/api/messages.py 14–67, 69–111

- **至少兩個安全測試案例**
- 篡改偵測（完整性/AAD 綁定）
  - 步驟：加密後任意改動 ciphertext 或 associated_data，再嘗試解密。
  - 預期：AESGCM.decrypt() 丟出例外，解密失敗（client/crypto_utils.py 117–124）。
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
