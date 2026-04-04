import os
import secrets
from datetime import timedelta

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
    SQLALCHEMY_DATABASE_URI = f'sqlite:///{os.path.join(BASE_DIR, "app.db")}'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or secrets.token_hex(32)
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=24)

    MAX_CONTENT_LENGTH = 1 * 1024 * 1024
    MAX_MESSAGE_SIZE = 64 * 1024
    MAX_USERNAME_LENGTH = 32
    MIN_PASSWORD_LENGTH = 8

    RATELIMIT_ENABLED = True
    RATELIMIT_STORAGE_URL = 'memory://'
    RATELIMIT_DEFAULT = '100 per minute'
    RATELIMIT_REGISTRATION = '5 per hour'
    RATELIMIT_LOGIN = '10 per minute'
    RATELIMIT_FRIEND_REQUEST = '20 per hour'
