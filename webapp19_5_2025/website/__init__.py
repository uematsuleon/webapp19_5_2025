from flask import Flask,session,redirect,url_for,request
from flask_login import current_user
from flask_sqlalchemy import SQLAlchemy
from os import path
from flask_login import LoginManager
from itsdangerous import URLSafeTimedSerializer as Serializer
from flask_mail import Mail
from flask_bcrypt import Bcrypt
from flask_session import Session
from flask_migrate import Migrate
from datetime import timedelta



app = None
bcrypt = Bcrypt(app)
db = SQLAlchemy(app)
DB_NAME = "database.db"

migrate = Migrate(app, db)




def create_app():
    global app
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'hjshjhdjah kjshkjdhjs'
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_NAME}'

    db.init_app(app)
    app.config["SESSION_PERMANENT"] = False
    app.config["SESSION_TYPE"] = "filesystem"
    Session(app)
    app.config.update(
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax',
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=60),  # Adjust session timeout as needed
        REMEMBER_COOKIE_SECURE=True,
        REMEMBER_COOKIE_HTTPONLY=True,
        REMEMBER_COOKIE_DURATION=timedelta(days=14)
    )


    from .views import views
    from .auth import auth

    app.register_blueprint(views, url_prefix='/')
    app.register_blueprint(auth, url_prefix='/')

    from .models import User, Note
    
    with app.app_context():
        db.create_all()

    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)



    @login_manager.user_loader
    def load_user(id):
        return User.query.get(int(id))

    @app.route('/')
    def index():

        return redirect(url_for('auth.login'))


    @app.after_request
    def add_security_headers(response):
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate, private'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        return response

    @app.before_request
    def check_user_auth():
        # List of routes that don't need authentication
        public_routes = ['auth.login', 'auth.signup', 'static']

        # If the endpoint requires login and user is not authenticated
        if not any(request.endpoint and request.endpoint.startswith(route) for route in public_routes):
            if not current_user.is_authenticated:
                return redirect(url_for('auth.login'))

    return app


def create_database(app):
    if not path.exists('website/' + DB_NAME):
        db.create_all(app=app)
        print('Created Database!')





