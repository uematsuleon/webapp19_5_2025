from flask import Flask, redirect, url_for, request, render_template
from flask_login import LoginManager, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_session import Session
from datetime import timedelta
from os import path

db = SQLAlchemy()
bcrypt = Bcrypt()
DB_NAME = "database.db"


def create_app():
    app = Flask(__name__)

    # Basic Config
    app.config['SECRET_KEY'] = 'hjshjhdjah kjshkjdhjs'
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_NAME}'
    app.config["SESSION_PERMANENT"] = False
    app.config["SESSION_TYPE"] = "filesystem"
    app.config.update(
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax',
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=60),
        REMEMBER_COOKIE_SECURE=True,
        REMEMBER_COOKIE_HTTPONLY=True,
        REMEMBER_COOKIE_DURATION=timedelta(days=14)
    )

    # Initialize extensions
    db.init_app(app)
    bcrypt.init_app(app)
    Session(app)

    # Register blueprints
    from .views import views
    from .auth import auth
    app.register_blueprint(views, url_prefix='/')
    app.register_blueprint(auth, url_prefix='/auth')

    # Models
    from .models import User, Note
    with app.app_context():
        db.create_all()

    # Login manager
    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    @app.route('/')
    def index():
        return redirect(url_for('auth.login'))

    # Security headers
    @app.after_request
    def add_security_headers(response):
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate, private'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        return response

    # Optional: error handler
    @app.errorhandler(404)
    def page_not_found(e):
        return "<h1>404 - Page Not Found</h1>", 404

    return app






