import io
import re
import base64
import pyotp
import qrcode
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from models import db, User

auth_bp = Blueprint('auth', __name__)
ph = PasswordHasher()

USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_]{3,32}$')


@auth_bp.route('/register', methods=['POST'])
def register():
    from app import limiter
    limiter.limit('5 per hour')(lambda: None)()

    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid request'}), 400

    username = data.get('username', '').strip()
    password = data.get('password', '')

    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400

    if not USERNAME_PATTERN.match(username):
        return jsonify({'error': 'Username must be 3-32 alphanumeric characters or underscores'}), 400

    if len(password) < 8 or len(password) > 128:
        return jsonify({'error': 'Password must be 8-128 characters'}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'Username already taken'}), 409

    otp_secret = pyotp.random_base32()
    password_hash = ph.hash(password)

    user = User(
        username=username,
        password_hash=password_hash,
        otp_secret=otp_secret,
    )
    db.session.add(user)
    db.session.commit()

    totp = pyotp.TOTP(otp_secret)
    provisioning_uri = totp.provisioning_uri(name=username, issuer_name='SecureChat')

    img = qrcode.make(provisioning_uri)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    qr_b64 = base64.b64encode(buf.getvalue()).decode('utf-8')

    return jsonify({
        'message': 'Registration successful',
        'user_id': user.id,
        'otp_secret': otp_secret,
        'qr_code': qr_b64,
    }), 201


@auth_bp.route('/login', methods=['POST'])
def login():
    from app import limiter
    limiter.limit('10 per minute')(lambda: None)()

    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid request'}), 400

    username = data.get('username', '').strip()
    password = data.get('password', '')
    otp_code = data.get('otp_code', '')

    skip_otp = current_app.config.get('SKIP_OTP', False)

    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400

    if len(username) > 32 or len(password) > 128:
        return jsonify({'error': 'Invalid credentials'}), 401

    if not skip_otp and not otp_code:
        return jsonify({'error': 'OTP code required'}), 400

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

    if ph.check_needs_rehash(user.password_hash):
        user.password_hash = ph.hash(password)
        db.session.commit()

    user.is_online = True
    db.session.commit()

    access_token = create_access_token(identity=str(user.id))
    return jsonify({
        'access_token': access_token,
        'user_id': user.id,
        'username': user.username,
    }), 200


@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    user_id = int(get_jwt_identity())
    user = User.query.get(user_id)
    if user:
        user.is_online = False
        from datetime import datetime
        user.last_seen = datetime.utcnow()
        db.session.commit()
    return jsonify({'message': 'Logged out'}), 200
