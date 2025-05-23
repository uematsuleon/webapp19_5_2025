from flask import Blueprint, render_template, request, flash, jsonify, redirect,url_for,make_response
from flask_login import login_required, current_user
from .models import Note
from . import db
import json
from functools import wraps

views = Blueprint('views', __name__)

def no_cache(view):
    @wraps(view)
    def no_cache_impl(*args, **kwargs):
        response = make_response(view(*args, **kwargs))
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response
    return no_cache_impl

@views.before_request
def allow_exception():
    if request.endpoint == "home" and request.args.get("new_user") == "true":
        return
    if not current_user.is_authenticated:
        return redirect(url_for("auth.login"))

@views.route('/', methods=['GET', 'POST'])
@login_required
@no_cache
def home():
    if request.method == 'POST': 
        note = request.form.get('note')#Gets the note from the HTML 

        if len(note) < 1:
            flash('Note is too short!', category='error') 
        else:
            new_note = Note(data=note, user_id=current_user.id)  #providing the schema for the note 
            db.session.add(new_note) #adding the note to the database 
            db.session.commit()
            flash('Note added!', category='success')

    return render_template("home.html", user=current_user)


@views.route('/delete-note', methods=['POST'])
def delete_note():  
    note = json.loads(request.data) # this function expects a JSON from the INDEX.js file 
    noteId = note['noteId']
    note = Note.query.get(noteId)
    if note:
        if note.user_id == current_user.id:
            db.session.delete(note)
            db.session.commit()

    return jsonify({})
