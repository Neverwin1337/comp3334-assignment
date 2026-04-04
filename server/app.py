import argparse
import logging
from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from config import Config
from models import db
from api.auth import auth_bp
from api.keys import keys_bp
from api.friends import friends_bp
from api.messages import messages_bp

logging.basicConfig(level=logging.WARNING)
logging.getLogger('werkzeug').setLevel(logging.WARNING)

limiter = Limiter(
    key_func=get_remote_address,
    storage_uri='memory://',
    default_limits=['100 per minute'],
)


def create_app(skip_otp=False):
    app = Flask(__name__)
    app.config.from_object(Config)
    app.config['SKIP_OTP'] = skip_otp

    db.init_app(app)
    JWTManager(app)
    limiter.init_app(app)

    @app.before_request
    def validate_json():
        if request.method in ['POST', 'PUT', 'PATCH']:
            if request.content_length and request.content_length > app.config.get('MAX_CONTENT_LENGTH', 1024 * 1024):
                return jsonify({'error': 'Request too large'}), 413
            if request.is_json:
                try:
                    request.get_json()
                except Exception:
                    return jsonify({'error': 'Invalid JSON'}), 400

    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(keys_bp, url_prefix='/api/keys')
    app.register_blueprint(friends_bp, url_prefix='/api/friends')
    app.register_blueprint(messages_bp, url_prefix='/api/messages')

    with app.app_context():
        db.create_all()

    return app


def generate_self_signed_cert():
    import os
    cert_file = os.path.join(os.path.dirname(__file__), 'cert.pem')
    key_file = os.path.join(os.path.dirname(__file__), 'key.pem')

    if os.path.exists(cert_file) and os.path.exists(key_file):
        return cert_file, key_file

    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    from datetime import datetime, timedelta

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, 'US'),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, 'State'),
        x509.NameAttribute(NameOID.LOCALITY_NAME, 'City'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'SecureChat'),
        x509.NameAttribute(NameOID.COMMON_NAME, 'localhost'),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName('localhost'),
                x509.IPAddress(ipaddress.IPv4Address('127.0.0.1')),
            ]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    with open(key_file, 'wb') as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    with open(cert_file, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    return cert_file, key_file


if __name__ == '__main__':
    import ipaddress
    parser = argparse.ArgumentParser()
    parser.add_argument('--skip-otp', action='store_true', help='Skip OTP verification for login')
    parser.add_argument('--no-tls', action='store_true', help='Disable TLS (not recommended)')
    args = parser.parse_args()

    if args.skip_otp:
        print('[WARNING] OTP verification is DISABLED')

    app = create_app(skip_otp=args.skip_otp)

    if args.no_tls:
        print('[WARNING] TLS is DISABLED - connections are not encrypted')
        app.run(host='0.0.0.0', port=5000, debug=False)
    else:
        cert_file, key_file = generate_self_signed_cert()
        print('[INFO] Running with TLS enabled')
        app.run(host='0.0.0.0', port=5000, debug=False, ssl_context=(cert_file, key_file))
