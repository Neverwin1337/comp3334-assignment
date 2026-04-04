from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from models import db, Message, Friendship, User

ONLINE_TIMEOUT = timedelta(seconds=10)

messages_bp = Blueprint('messages', __name__)


MAX_MESSAGE_SIZE = 64 * 1024


@messages_bp.route('/send', methods=['POST'])
@jwt_required()
def send_message():
    user_id = int(get_jwt_identity())
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid request'}), 400

    receiver_id = data.get('receiver_id')
    ciphertext = data.get('ciphertext')
    nonce = data.get('nonce')
    ephemeral_key = data.get('ephemeral_key')
    message_type = data.get('message_type', 'normal')
    self_destruct_seconds = data.get('self_destruct_seconds')

    if not receiver_id or not ciphertext or not nonce:
        return jsonify({'error': 'Missing required fields'}), 400

    if not isinstance(receiver_id, int) or receiver_id <= 0:
        return jsonify({'error': 'Invalid receiver_id'}), 400

    if len(ciphertext) > MAX_MESSAGE_SIZE:
        return jsonify({'error': 'Message too large'}), 400

    if message_type not in ('normal', 'initial'):
        return jsonify({'error': 'Invalid message type'}), 400

    if self_destruct_seconds is not None:
        if not isinstance(self_destruct_seconds, int) or self_destruct_seconds < 1 or self_destruct_seconds > 604800:
            return jsonify({'error': 'Invalid self_destruct_seconds (1-604800)'}), 400

    friendship = Friendship.query.filter_by(user_id=user_id, friend_id=receiver_id).first()
    if not friendship:
        return jsonify({'error': 'Not friends with this user'}), 403

    msg = Message(
        sender_id=user_id,
        receiver_id=receiver_id,
        ciphertext=ciphertext,
        nonce=nonce,
        ephemeral_key=ephemeral_key,
        message_type=message_type,
        self_destruct_seconds=self_destruct_seconds,
        status='sent',
    )
    db.session.add(msg)
    db.session.commit()

    return jsonify({
        'message_id': msg.id,
        'status': 'sent',
        'created_at': msg.created_at.isoformat(),
    }), 201


@messages_bp.route('/fetch', methods=['GET'])
@jwt_required()
def fetch_messages():
    user_id = int(get_jwt_identity())

    user = User.query.get(user_id)
    if user:
        user.is_online = True
        user.last_seen = datetime.utcnow()
        db.session.commit()

    now = datetime.utcnow()
    expired = Message.query.filter(
        Message.self_destruct_seconds.isnot(None),
        Message.delivered_at.isnot(None),
    ).all()
    for msg in expired:
        expire_time = msg.delivered_at + timedelta(seconds=msg.self_destruct_seconds)
        if now > expire_time:
            db.session.delete(msg)
    db.session.commit()

    messages = Message.query.filter_by(receiver_id=user_id, status='sent').order_by(
        Message.created_at.asc()
    ).all()

    result = []
    for msg in messages:
        msg.status = 'delivered'
        msg.delivered_at = datetime.utcnow()
        result.append({
            'message_id': msg.id,
            'sender_id': msg.sender_id,
            'ciphertext': msg.ciphertext,
            'nonce': msg.nonce,
            'ephemeral_key': msg.ephemeral_key,
            'message_type': msg.message_type,
            'self_destruct_seconds': msg.self_destruct_seconds,
            'created_at': msg.created_at.isoformat(),
        })

    db.session.commit()
    return jsonify({'messages': result}), 200


@messages_bp.route('/history/<int:friend_id>', methods=['GET'])
@jwt_required()
def get_history(friend_id):
    user_id = int(get_jwt_identity())
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)

    messages = Message.query.filter(
        db.or_(
            db.and_(Message.sender_id == user_id, Message.receiver_id == friend_id),
            db.and_(Message.sender_id == friend_id, Message.receiver_id == user_id),
        )
    ).order_by(Message.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)

    result = []
    for msg in messages.items:
        result.append({
            'message_id': msg.id,
            'sender_id': msg.sender_id,
            'receiver_id': msg.receiver_id,
            'ciphertext': msg.ciphertext,
            'nonce': msg.nonce,
            'ephemeral_key': msg.ephemeral_key,
            'message_type': msg.message_type,
            'self_destruct_seconds': msg.self_destruct_seconds,
            'status': msg.status,
            'created_at': msg.created_at.isoformat(),
        })

    return jsonify({'messages': result, 'total': messages.total}), 200


@messages_bp.route('/status/<int:message_id>', methods=['GET'])
@jwt_required()
def get_message_status(message_id):
    user_id = int(get_jwt_identity())
    msg = Message.query.get(message_id)
    if not msg or msg.sender_id != user_id:
        return jsonify({'error': 'Message not found'}), 404

    return jsonify({
        'message_id': msg.id,
        'status': msg.status,
        'delivered_at': msg.delivered_at.isoformat() if msg.delivered_at else None,
    }), 200


@messages_bp.route('/conversations', methods=['GET'])
@jwt_required()
def get_conversations():
    user_id = int(get_jwt_identity())

    from sqlalchemy import func, case

    subq = db.session.query(
        case(
            (Message.sender_id == user_id, Message.receiver_id),
            else_=Message.sender_id,
        ).label('friend_id'),
        func.max(Message.id).label('last_msg_id'),
        func.sum(
            case(
                (db.and_(Message.receiver_id == user_id, Message.status.in_(['sent', 'delivered'])), 1),
                else_=0,
            )
        ).label('unread_count'),
    ).filter(
        db.or_(Message.sender_id == user_id, Message.receiver_id == user_id)
    ).group_by('friend_id').subquery()

    results = db.session.query(
        subq.c.friend_id,
        subq.c.last_msg_id,
        subq.c.unread_count,
        User.username,
        User.last_seen,
    ).join(User, User.id == subq.c.friend_id).all()

    now = datetime.utcnow()
    conversations = []
    for r in results:
        last_msg = Message.query.get(r.last_msg_id)
        is_online = r.last_seen and (now - r.last_seen) < ONLINE_TIMEOUT
        conversations.append({
            'friend_id': r.friend_id,
            'friend_username': r.username,
            'is_online': is_online,
            'unread_count': r.unread_count,
            'last_message_time': last_msg.created_at.isoformat() if last_msg else None,
            'last_message_id': r.last_msg_id,
        })

    conversations.sort(key=lambda x: x['last_message_time'] or '', reverse=True)
    return jsonify({'conversations': conversations}), 200


@messages_bp.route('/ack', methods=['POST'])
@jwt_required()
def ack_messages():
    user_id = int(get_jwt_identity())
    data = request.get_json()
    message_ids = data.get('message_ids', [])

    Message.query.filter(
        Message.id.in_(message_ids),
        Message.receiver_id == user_id,
    ).update({Message.status: 'read'}, synchronize_session=False)
    db.session.commit()

    return jsonify({'message': 'Acknowledged'}), 200


@messages_bp.route('/sent_status', methods=['GET'])
@jwt_required()
def get_sent_status():
    user_id = int(get_jwt_identity())

    messages = Message.query.filter(
        Message.sender_id == user_id,
        Message.status.in_(['delivered', 'read']),
    ).all()

    result = []
    for msg in messages:
        result.append({
            'message_id': msg.id,
            'status': msg.status,
        })

    return jsonify({'statuses': result}), 200
