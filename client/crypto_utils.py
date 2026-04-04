import os
import json
import base64
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization


def generate_x25519_keypair():
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def generate_ed25519_keypair():
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def pub_to_b64(public_key):
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode('utf-8')


def priv_to_b64(private_key):
    raw = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return base64.b64encode(raw).decode('utf-8')


def b64_to_x25519_pub(b64_str):
    raw = base64.b64decode(b64_str)
    return X25519PublicKey.from_public_bytes(raw)


def b64_to_x25519_priv(b64_str):
    raw = base64.b64decode(b64_str)
    return X25519PrivateKey.from_private_bytes(raw)


def b64_to_ed25519_pub(b64_str):
    raw = base64.b64decode(b64_str)
    return Ed25519PublicKey.from_public_bytes(raw)


def b64_to_ed25519_priv(b64_str):
    raw = base64.b64decode(b64_str)
    return Ed25519PrivateKey.from_private_bytes(raw)


def sign_key(signing_private_key, public_key_to_sign):
    pub_bytes = public_key_to_sign.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    signature = signing_private_key.sign(pub_bytes)
    return base64.b64encode(signature).decode('utf-8')


def verify_signature(signing_public_key_b64, signature_b64, signed_key_b64):
    signing_pub = b64_to_ed25519_pub(signing_public_key_b64)
    signature = base64.b64decode(signature_b64)
    signed_key_bytes = base64.b64decode(signed_key_b64)
    try:
        signing_pub.verify(signature, signed_key_bytes)
        return True
    except Exception:
        return False


def generate_fingerprint(identity_public_key_b64):
    import hashlib
    key_bytes = base64.b64decode(identity_public_key_b64.split(':')[-1])
    digest = hashlib.sha256(key_bytes).hexdigest().upper()
    return ' '.join([digest[i:i+4] for i in range(0, 32, 4)])


def x25519_derive_shared(private_key, public_key):
    return private_key.exchange(public_key)


def kdf_derive(shared_secrets, info=b'SecureChat'):
    ikm = b''.join(shared_secrets)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'\x00' * 32,
        info=info,
    )
    return hkdf.derive(ikm)


def aes_encrypt(key, plaintext, associated_data=None):
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    if associated_data and isinstance(associated_data, str):
        associated_data = associated_data.encode('utf-8')
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
    return (
        base64.b64encode(ciphertext).decode('utf-8'),
        base64.b64encode(nonce).decode('utf-8'),
    )


def aes_decrypt(key, ciphertext_b64, nonce_b64, associated_data=None):
    aesgcm = AESGCM(key)
    ciphertext = base64.b64decode(ciphertext_b64)
    nonce = base64.b64decode(nonce_b64)
    if associated_data and isinstance(associated_data, str):
        associated_data = associated_data.encode('utf-8')
    plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data)
    return plaintext.decode('utf-8')


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


def encrypt_backup(plaintext_json, passphrase):
    key, salt = derive_key_from_passphrase(passphrase)
    ciphertext_b64, nonce_b64 = aes_encrypt(key, plaintext_json)
    salt_b64 = base64.b64encode(salt).decode('utf-8')
    return ciphertext_b64, nonce_b64, salt_b64


def decrypt_backup(ciphertext_b64, nonce_b64, salt_b64, passphrase):
    salt = base64.b64decode(salt_b64)
    key, _ = derive_key_from_passphrase(passphrase, salt)
    return aes_decrypt(key, ciphertext_b64, nonce_b64)


class KeyBundle:
    def __init__(self):
        self.identity_private_key = None
        self.identity_public_key = None
        self.signing_private_key = None
        self.signing_public_key = None
        self.signed_prekey_private = None
        self.signed_prekey_public = None
        self.signed_prekey_sig = None
        self.one_time_prekeys = []

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

    def _get_key_data(self):
        return {
            'identity_private_key': priv_to_b64(self.identity_private_key),
            'identity_public_key': pub_to_b64(self.identity_public_key),
            'signing_private_key': priv_to_b64(self.signing_private_key),
            'signing_public_key': pub_to_b64(self.signing_public_key),
            'signed_prekey_private': priv_to_b64(self.signed_prekey_private),
            'signed_prekey_public': pub_to_b64(self.signed_prekey_public),
            'signed_prekey_sig': self.signed_prekey_sig,
            'one_time_prekeys': [
                {
                    'key_id': otpk['key_id'],
                    'private': priv_to_b64(otpk['private']),
                    'public': pub_to_b64(otpk['public']),
                }
                for otpk in self.one_time_prekeys
            ],
        }

    def save_to_file(self, filepath, passphrase=None):
        data = self._get_key_data()
        if passphrase:
            plaintext = json.dumps(data)
            ciphertext_b64, nonce_b64, salt_b64 = encrypt_backup(plaintext, passphrase)
            encrypted_data = {
                'encrypted': True,
                'ciphertext': ciphertext_b64,
                'nonce': nonce_b64,
                'salt': salt_b64,
            }
            with open(filepath, 'w') as f:
                json.dump(encrypted_data, f, indent=2)
        else:
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2)

    def load_from_file(self, filepath, passphrase=None):
        with open(filepath, 'r') as f:
            file_data = json.load(f)

        if file_data.get('encrypted'):
            if not passphrase:
                raise ValueError('Passphrase required for encrypted key file')
            plaintext = decrypt_backup(
                file_data['ciphertext'],
                file_data['nonce'],
                file_data['salt'],
                passphrase
            )
            data = json.loads(plaintext)
        else:
            data = file_data

        self.identity_private_key = b64_to_x25519_priv(data['identity_private_key'])
        self.identity_public_key = self.identity_private_key.public_key()
        self.signing_private_key = b64_to_ed25519_priv(data['signing_private_key'])
        self.signing_public_key = self.signing_private_key.public_key()
        self.signed_prekey_private = b64_to_x25519_priv(data['signed_prekey_private'])
        self.signed_prekey_public = self.signed_prekey_private.public_key()
        self.signed_prekey_sig = data['signed_prekey_sig']
        self.one_time_prekeys = []
        for otpk in data['one_time_prekeys']:
            priv = b64_to_x25519_priv(otpk['private'])
            self.one_time_prekeys.append({
                'key_id': otpk['key_id'],
                'private': priv,
                'public': priv.public_key(),
            })


class SessionCipher:
    def __init__(self):
        self.shared_key = None

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

    def encrypt(self, plaintext, associated_data=None):
        if not self.shared_key:
            raise ValueError('Session not initialized')
        return aes_encrypt(self.shared_key, plaintext, associated_data)

    def decrypt(self, ciphertext_b64, nonce_b64, associated_data=None):
        if not self.shared_key:
            raise ValueError('Session not initialized')
        return aes_decrypt(self.shared_key, ciphertext_b64, nonce_b64, associated_data)
