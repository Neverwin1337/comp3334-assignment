from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from models import db, User, FriendRequest, Friendship

ONLINE_TIMEOUT = timedelta(seconds=10)

friends_bp = Blueprint('friends', __name__)


@friends_bp.route('/request', methods=['POST'])
@jwt_required()
def send_friend_request():
    from app import limiter
    from models import BlockedUser
    limiter.limit('20 per hour')(lambda: None)()

    user_id = int(get_jwt_identity())
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid request'}), 400

    target_username = data.get('username', '').strip()

    if not target_username or len(target_username) > 32:
        return jsonify({'error': 'Invalid username'}), 400

    target = User.query.filter_by(username=target_username).first()
    if not target:
        return jsonify({'error': 'User not found'}), 404

    if target.id == user_id:
        return jsonify({'error': 'Cannot add yourself'}), 400

    blocked = BlockedUser.query.filter_by(user_id=target.id, blocked_id=user_id).first()
    if blocked:
        return jsonify({'error': 'Cannot send request to this user'}), 403

    existing = Friendship.query.filter_by(user_id=user_id, friend_id=target.id).first()
    if existing:
        return jsonify({'error': 'Already friends'}), 409

    pending = FriendRequest.query.filter_by(
        from_user_id=user_id, to_user_id=target.id, status='pending'
    ).first()
    if pending:
        return jsonify({'error': 'Request already sent'}), 409

    reverse = FriendRequest.query.filter_by(
        from_user_id=target.id, to_user_id=user_id, status='pending'
    ).first()
    if reverse:
        reverse.status = 'accepted'
        db.session.add(Friendship(user_id=user_id, friend_id=target.id))
        db.session.add(Friendship(user_id=target.id, friend_id=user_id))
        db.session.commit()
        return jsonify({'message': 'Friend added (mutual request)'}), 200

    fr = FriendRequest(from_user_id=user_id, to_user_id=target.id)
    db.session.add(fr)
    db.session.commit()
    return jsonify({'message': 'Friend request sent'}), 201


@friends_bp.route('/requests', methods=['GET'])
@jwt_required()
def get_friend_requests():
    user_id = int(get_jwt_identity())
    pending = FriendRequest.query.filter_by(to_user_id=user_id, status='pending').all()
    result = []
    for fr in pending:
        result.append({
            'id': fr.id,
            'from_user_id': fr.from_user_id,
            'from_username': fr.from_user.username,
            'created_at': fr.created_at.isoformat(),
        })
    return jsonify({'requests': result}), 200


@friends_bp.route('/respond', methods=['POST'])
@jwt_required()
def respond_friend_request():
    user_id = int(get_jwt_identity())
    data = request.get_json()
    request_id = data.get('request_id')
    action = data.get('action')  # accept or decline

    if action not in ('accept', 'decline'):
        return jsonify({'error': 'Action must be accept or decline'}), 400

    fr = FriendRequest.query.get(request_id)
    if not fr or fr.to_user_id != user_id or fr.status != 'pending':
        return jsonify({'error': 'Invalid request'}), 404

    if action == 'accept':
        fr.status = 'accepted'
        db.session.add(Friendship(user_id=user_id, friend_id=fr.from_user_id))
        db.session.add(Friendship(user_id=fr.from_user_id, friend_id=user_id))
        db.session.commit()
        return jsonify({'message': 'Friend request accepted'}), 200
    else:
        fr.status = 'declined'
        db.session.commit()
        return jsonify({'message': 'Friend request declined'}), 200


@friends_bp.route('/list', methods=['GET'])
@jwt_required()
def list_friends():
    user_id = int(get_jwt_identity())
    friendships = Friendship.query.filter_by(user_id=user_id).all()
    result = []
    now = datetime.utcnow()
    for f in friendships:
        friend = f.friend
        is_online = friend.last_seen and (now - friend.last_seen) < ONLINE_TIMEOUT
        result.append({
            'user_id': friend.id,
            'username': friend.username,
            'is_online': is_online,
            'last_seen': friend.last_seen.isoformat() if friend.last_seen else None,
        })
    return jsonify({'friends': result}), 200


@friends_bp.route('/remove', methods=['POST'])
@jwt_required()
def remove_friend():
    user_id = int(get_jwt_identity())
    data = request.get_json()
    friend_id = data.get('friend_id')

    if not friend_id:
        return jsonify({'error': 'friend_id required'}), 400

    Friendship.query.filter_by(user_id=user_id, friend_id=friend_id).delete()
    Friendship.query.filter_by(user_id=friend_id, friend_id=user_id).delete()
    db.session.commit()
    return jsonify({'message': 'Friend removed'}), 200


@friends_bp.route('/block', methods=['POST'])
@jwt_required()
def block_user():
    from models import BlockedUser
    user_id = int(get_jwt_identity())
    data = request.get_json()
    target_id = data.get('user_id')

    if not target_id:
        return jsonify({'error': 'user_id required'}), 400

    existing = BlockedUser.query.filter_by(user_id=user_id, blocked_id=target_id).first()
    if existing:
        return jsonify({'error': 'User already blocked'}), 409

    Friendship.query.filter_by(user_id=user_id, friend_id=target_id).delete()
    Friendship.query.filter_by(user_id=target_id, friend_id=user_id).delete()
    FriendRequest.query.filter_by(from_user_id=target_id, to_user_id=user_id).delete()

    db.session.add(BlockedUser(user_id=user_id, blocked_id=target_id))
    db.session.commit()
    return jsonify({'message': 'User blocked'}), 200


@friends_bp.route('/unblock', methods=['POST'])
@jwt_required()
def unblock_user():
    from models import BlockedUser
    user_id = int(get_jwt_identity())
    data = request.get_json()
    target_id = data.get('user_id')

    BlockedUser.query.filter_by(user_id=user_id, blocked_id=target_id).delete()
    db.session.commit()
    return jsonify({'message': 'User unblocked'}), 200
