from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User,Verification
from .forms import ResetPasswordForm,ConfirmEmailForm
from werkzeug.security import generate_password_hash, check_password_hash
from . import db   ##means from __init__.py import db
from flask_login import login_user, login_required, logout_user, current_user
from flask import  session,make_response
from functools import wraps

import random
import smtplib
from email.mime.text import MIMEText

from datetime import datetime,timedelta


auth = Blueprint('auth', __name__)

def no_cache(view):
    @wraps(view)
    def no_cache_impl(*args, **kwargs):
        response = make_response(view(*args, **kwargs))
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response
    return no_cache_impl

def prevent_back_history():
    response = make_response(...)  # Your existing response
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response
# Add this function to check if user is already logged in
def redirect_if_logged_in(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated:
            return redirect(url_for('views.home'))
        return f(*args, **kwargs)
    return decorated_function

@auth.route('/')
def home():
    return redirect(url_for('login'))


@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('Logged in successfully!', category='success')
                login_user(user, remember=True)
                session['user_id'] = user.id
                print('session started')
                response = make_response(redirect(url_for('views.home')))
                response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
                response.headers['Pragma'] = 'no-cache'
                response.headers['Expires'] = '0'

                return redirect(url_for('views.home'))
            else:
                flash('Incorrect password, try again.', category='error')
        else:
            flash('Email does not exist.', category='error')

    return render_template("login.html", user=current_user)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    print('session ended')
    response = make_response(redirect(url_for('auth.login')))
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    response.set_cookie('session','',expires=0)

    return response




def send_six_digit(email,code):
    smtp_server = "smtp.gmail.com"
    smtp_port = 587
    sender_email = "uematsuleon@gmail.com"
    sender_password = "gvyy mtur zvys hoki"
    recipient_email = email


    email_body = f"""Please type this code
    {code}
    If you did not make this request, simply ignore this email and no changes will be made.
    """

    msg = MIMEText(email_body)
    msg["Subject"] = "6 digit code"
    msg["From"] = sender_email
    msg["To"] = recipient_email


    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()  # Secure connection
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, recipient_email, msg.as_string())

    print("Password confirmation email sent successfully!")

@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists.', category='error')
        elif len(email) < 4:
            flash('Email must be greater than 3 characters.', category='error')
        elif len(first_name) < 2:
            flash('First name must be greater than 1 character.', category='error')
        elif password1 != password2:
            flash('Passwords don\'t match.', category='error')
        elif len(password1) < 7:
            flash('Password must be at least 7 characters.', category='error')
        else:
            #new_user = User(email=email, first_name=first_name, password=generate_password_hash(password1, method='pbkdf2:sha256'))
            code = f"{random.randint(100000, 999999)}"
            session['temp_user'] = {
                'email': email,
                'password': password1,
                'first_name': first_name,
                'code': code
            }
            #db.session.commit()
            #login_user(new_user, remember=True)
            #flash('Account created!', category='success')
            #recipient_email = request.form["email"]

            send_six_digit(email,code)
            print(code)
            print(session['temp_user'])

            return redirect(url_for('auth.confirm_email',email = email))

    return render_template("sign_up.html", user=current_user)


@auth.route('/confirm-email', methods=['GET', 'POST'])
def confirm_email():
    form = ConfirmEmailForm()
    temp_user = session.get('temp_user')

    print("Form submitted:", form.is_submitted())  # Debug print
    print("Form validated:", form.validate())  # Debug print
    print("Temp user:", temp_user)  # Debug print

    if not temp_user:
        flash("セッションの有効期限が切れました。最初からやり直してください。", 'error')
        return redirect(url_for('auth.sign_up'))

    if form.validate_on_submit():
        print("Form data:", form.data)  # Debug print

        # Check which button was clicked
        if form.verify.data:
            print("Verify button clicked")  # Debug print
            input_code = form.code.data
            print("Input code:", input_code)  # Debug print
            print("Stored code:", temp_user['code'])  # Debug print

            # Convert both to strings for comparison
            if str(input_code) == str(temp_user['code']):
                try:
                    new_user = User(
                        email=temp_user['email'],
                        first_name=temp_user['first_name'],
                        password=generate_password_hash(temp_user['password'], method='pbkdf2:sha256'),
                    )
                    db.session.add(new_user)
                    db.session.commit()
                    login_user(new_user, remember=True)
                    session.pop('temp_user', None)
                    flash("メールの確認が完了しました！ログインしました。", 'success')
                    return redirect(url_for('views.home'))
                except Exception as e:
                    print("Database error:", str(e))  # Debug print
                    db.session.rollback()
                    flash("エラーが発生しました。もう一度お試しください。", 'error')
            else:
                flash("無効なコードです。", 'error')
                return render_template("confirm_email.html", user=current_user, form=form)

        elif form.resend.data:
            print("Resend button clicked")  # Debug print
            new_code = f"{random.randint(100000, 999999)}"
            temp_user['code'] = new_code
            session['temp_user'] = temp_user
            send_six_digit(temp_user['email'], new_code)
            flash("確認コードを再送信しました。", 'success')
            return render_template("confirm_email.html", user=current_user, form=form)

    return render_template("confirm_email.html", user=current_user, form=form)


@auth.route('/new-password', methods=['GET', 'POST'])
def new_password():
    return render_template('new_password.html')

def send_reset_email(user):
    smtp_server = "smtp.gmail.com"
    smtp_port = 587
    sender_email = "uematsuleon@gmail.com"
    sender_password = "gvyy mtur zvys hoki"  # Use an App Password instead of a regular password
    recipient_email = user.email

    # Generate reset token
    token = user.get_reset_token()
    reset_url = url_for('auth.reset_token', token=token, _external=True)

    # Create the email body
    email_body = f"""To reset your password, visit the following link:
    {reset_url}

    If you did not make this request, simply ignore this email and no changes will be made.
    """

    msg = MIMEText(email_body)
    msg["Subject"] = "Password Reset Request"
    msg["From"] = sender_email
    msg["To"] = recipient_email

    # Send email
    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()  # Secure connection
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, recipient_email, msg.as_string())

    print("Password reset email sent successfully!")

@auth.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            send_reset_email(user)
            flash('パスワードリセットのリンクをメールに送信しました。', 'success')
            print('this is your url')
        else:
            flash('このメールアドレスは登録されていません。', 'error')



    return render_template('reset_password.html',user=current_user)


@auth.route("/reset-password/<token>", methods=['GET', 'POST'])
def reset_token(token):
    print("Token received:", token)  # Debug print
    user = User.verify_reset_token(token)
    print("User found:", user)  # Debug print

    if user is None:
        flash('That is an invalid or expired token', 'error')
        return redirect(url_for('auth.reset_password'))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        try:
            print("Form validated successfully")  # Debug print
            print("password")
            password = form.password.data
            print("New password received (length):", len(password))  # Debug print safely
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            print("Password hashed successfully")  # Debug print

            # Explicitly query the user again to ensure we have the latest instance
            user = db.session.get(User, user.id)
            print(f'who is this {User}')
            user.password = hashed_password
            print("Password assigned to user")  # Debug print

            db.session.add(user)  # Explicitly add the user to the session
            db.session.commit()
            print("Database committed successfully")  # Debug print

            flash('Your password has been updated! You are now able to log in', 'success')
            return redirect(url_for('auth.login'))
        except Exception as e:
            print("Error updating password:", str(e))  # Debug print
            db.session.rollback()
            flash('An error occurred while updating your password.', 'error')
    else:
        print("Form validation errors:", form.errors)  # Debug print

    return render_template('reset_token.html', title='Reset Password', form=form)