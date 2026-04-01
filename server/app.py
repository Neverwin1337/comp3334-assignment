from flask import Flask
from flask_jwt_extended import JWTManager
from config import Config
from models import db
from api.auth import auth_bp
from api.keys import keys_bp
from api.friends import friends_bp
from api.messages import messages_bp


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    JWTManager(app)

    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(keys_bp, url_prefix='/api/keys')
    app.register_blueprint(friends_bp, url_prefix='/api/friends')
    app.register_blueprint(messages_bp, url_prefix='/api/messages')

    with app.app_context():
        db.create_all()

    return app


if __name__ == '__main__':
    app = create_app()
    app.run(host='0.0.0.0', port=5000, debug=True)
