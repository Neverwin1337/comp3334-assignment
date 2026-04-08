#!/usr/bin/env python3
"""
Database Initialization Script for SecureChat Server

This script initializes the SQLite database with all required tables.
Run this script before starting the server for the first time.

Usage:
    python init_db.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import create_app
from models import db, User, FriendRequest, Friendship, Message, KeyBundle, BlockedUser


def init_database():
    print('Initializing SecureChat database...')
    
    app = create_app(skip_otp=True)
    
    with app.app_context():
        db.create_all()
        
        print('Database tables created:')
        print('  - users')
        print('  - friend_requests')
        print('  - friendships')
        print('  - messages')
        print('  - key_bundles')
        print('  - blocked_users')
        
        db_path = app.config['SQLALCHEMY_DATABASE_URI'].replace('sqlite:///', '')
        print(f'\nDatabase file: {db_path}')
        print('\nDatabase initialization complete!')
        print('\nYou can now start the server with:')
        print('  python app.py --skip-otp --no-tls  (development mode)')
        print('  python app.py                       (production mode)')


if __name__ == '__main__':
    init_database()
