import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class ApiClient:
    def __init__(self, base_url='https://localhost:5000', verify_ssl=False):
        self.base_url = base_url
        self.token = None
        self.user_id = None
        self.username = None
        self.verify_ssl = verify_ssl

    def _headers(self):
        h = {'Content-Type': 'application/json'}
        if self.token:
            h['Authorization'] = f'Bearer {self.token}'
        return h

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

    def register(self, username, password):
        return self._post('/api/auth/register', {'username': username, 'password': password})

    def login(self, username, password, otp_code):
        data, status = self._post('/api/auth/login', {
            'username': username,
            'password': password,
            'otp_code': otp_code,
        })
        if status == 200:
            self.token = data['access_token']
            self.user_id = data['user_id']
            self.username = data['username']
        return data, status

    def logout(self):
        result = self._post('/api/auth/logout')
        self.token = None
        self.user_id = None
        self.username = None
        return result

    def upload_keys(self, key_data):
        return self._post('/api/keys/upload', key_data)

    def get_key_bundle(self, target_user_id):
        return self._get(f'/api/keys/bundle/{target_user_id}')

    def send_friend_request(self, username):
        return self._post('/api/friends/request', {'username': username})

    def get_friend_requests(self):
        return self._get('/api/friends/requests')

    def respond_friend_request(self, request_id, action):
        return self._post('/api/friends/respond', {'request_id': request_id, 'action': action})

    def list_friends(self):
        return self._get('/api/friends/list')

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

    def fetch_messages(self):
        return self._get('/api/messages/fetch')

    def get_history(self, friend_id, page=1, per_page=50):
        return self._get(f'/api/messages/history/{friend_id}', {'page': page, 'per_page': per_page})

    def get_message_status(self, message_id):
        return self._get(f'/api/messages/status/{message_id}')

    def get_conversations(self):
        return self._get('/api/messages/conversations')

    def ack_messages(self, message_ids):
        return self._post('/api/messages/ack', {'message_ids': message_ids})

    def upload_backup(self, encrypted_data, nonce, salt):
        return self._post('/api/keys/backup', {
            'encrypted_data': encrypted_data,
            'nonce': nonce,
            'salt': salt,
        })

    def download_backup(self):
        return self._get('/api/keys/backup')

    def get_sent_status(self):
        return self._get('/api/messages/sent_status')

    def remove_friend(self, friend_id):
        return self._post('/api/friends/remove', {'friend_id': friend_id})

    def block_user(self, user_id):
        return self._post('/api/friends/block', {'user_id': user_id})

    def unblock_user(self, user_id):
        return self._post('/api/friends/unblock', {'user_id': user_id})
