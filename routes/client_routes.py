from flask import Blueprint, request, session, redirect, url_for, flash
from models import mongo, check_db_connection
import uuid
import os
import re
from werkzeug.security import generate_password_hash

def validate_input_string(value, pattern=None, max_length=255):
    if not isinstance(value, str):
        return False
    if len(value) > max_length:
        return False
    if pattern and not re.match(pattern, value):
        return False
    return True

client_bp = Blueprint('client', __name__)

@client_bp.route('/create_client', methods=['POST'])
def create_client():
    if 'user_id' not in session:
        flash('You need to log in first.', 'error')
        return redirect(url_for('auth.login'))

    user_id = session['user_id']

    if not validate_input_string(user_id):
        flash('Invalid session. Please log in again.', 'error')
        return redirect(url_for('auth.login'))

    check_db_connection()
    user = mongo.db.users.find_one({'user_id': user_id})
    if not user or user.get('role') != 'admin':
        flash('You do not have permission to create a client.', 'error')
        return redirect(url_for('user.dashboard'))

    client_id = str(uuid.uuid4())
    user_id = session['user_id']

    plain_text_client_secret = os.urandom(24).hex()
    hashed_client_secret = generate_password_hash(plain_text_client_secret, method='pbkdf2:sha256', salt_length=16)

    mongo.db.clients.insert_one({
        'client_id': client_id,
        'client_secret': hashed_client_secret,
        'redirect_uri': request.form.get('redirect_uri'),
        'user_id': user_id
    })

    flash(f'Client ID: {client_id}', 'success')
    flash(f'<strong>Client Secret:</strong> <code>{plain_text_client_secret}</code>', 'info')
    return redirect(url_for('user.dashboard'))

@client_bp.route('/delete_client/<client_id>', methods=['POST'])
def delete_client(client_id):
    if 'user_id' not in session:
        flash('You need to log in first.', 'error')
        return redirect(url_for('auth.login'))

    check_db_connection()
    user = mongo.db.users.find_one({'user_id': session['user_id']})
    if not user or user.get('role') != 'admin':
        flash('You do not have permission to delete this client.', 'error')
        return redirect(url_for('user.dashboard'))

    client = mongo.db.clients.find_one({'client_id': client_id, 'user_id': session['user_id']})
    if not client:
        flash('You do not have permission to delete this client.', 'error')
        return redirect(url_for('user.dashboard'))

    mongo.db.clients.delete_one({'client_id': client_id})
    flash(f'Client {client_id} deleted successfully!', 'success')
    return redirect(url_for('user.dashboard'))