from . import db,app
from flask_login import UserMixin
from sqlalchemy.sql import func
from itsdangerous import URLSafeTimedSerializer as Serializer
from datetime import datetime,timedelta



class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    data = db.Column(db.String(10000))
    date = db.Column(db.DateTime(timezone=True), default=func.now())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

class Verification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    verification_code = db.Column(db.String(6))
    code_expires_at = db.Column(db.DateTime, default=lambda: datetime.utcnow() + timedelta(minutes=10))
    is_verified = db.Column(db.Boolean, default=False)

    user = db.relationship('User', backref=db.backref('verification', uselist=False))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(150))
    first_name = db.Column(db.String(150))
    notes = db.relationship('Note')

    def get_reset_token(self,expires_sec=1800):
        s = Serializer(app.config['SECRET_KEY'])
        # s = Serializer(app.config['SECRET_KEY'],expires_sec = 1800) didnt work
        return s.dumps({'user_id':self.id})

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None

        print(f"Found user: {User}")

        return User.query.get(user_id)

    def __repr__(self):
        return f'User ({self.email}, {self.first_name})'