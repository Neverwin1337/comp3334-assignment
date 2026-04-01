import time
from PySide6.QtCore import QObject, Signal


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
