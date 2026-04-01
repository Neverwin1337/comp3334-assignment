from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from datetime import datetime
from models import db, User, OneTimePreKey, KeyBackup

keys_bp = Blueprint('keys', __name__)


@keys_bp.route('/upload', methods=['POST'])
@jwt_required()
def upload_keys():
    user_id = int(get_jwt_identity())
    data = request.get_json()

    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    user.identity_public_key = data.get('identity_public_key')
    user.signed_prekey_public = data.get('signed_prekey_public')
    user.signed_prekey_sig = data.get('signed_prekey_sig')

    one_time_prekeys = data.get('one_time_prekeys', [])
    for otpk in one_time_prekeys:
        key = OneTimePreKey(
            user_id=user_id,
            key_id=otpk['key_id'],
            public_key=otpk['public_key'],
        )
        db.session.add(key)

    db.session.commit()
    return jsonify({'message': 'Keys uploaded'}), 200


@keys_bp.route('/bundle/<int:target_user_id>', methods=['GET'])
@jwt_required()
def get_key_bundle(target_user_id):
    user = User.query.get(target_user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    if not user.identity_public_key:
        return jsonify({'error': 'User has not uploaded keys'}), 404

    otpk = OneTimePreKey.query.filter_by(user_id=target_user_id, used=False).first()
    otpk_data = None
    if otpk:
        otpk_data = {'key_id': otpk.key_id, 'public_key': otpk.public_key}
        otpk.used = True
        db.session.commit()

    return jsonify({
        'user_id': user.id,
        'username': user.username,
        'identity_public_key': user.identity_public_key,
        'signed_prekey_public': user.signed_prekey_public,
        'signed_prekey_sig': user.signed_prekey_sig,
        'one_time_prekey': otpk_data,
    }), 200


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
        backup = KeyBackup(
            user_id=user_id,
            encrypted_data=encrypted_data,
            nonce=nonce,
            salt=salt,
        )
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
