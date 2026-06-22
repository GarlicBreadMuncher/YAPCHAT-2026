from flask import Flask, render_template, request, redirect, url_for, session
from flask_socketio import SocketIO, emit, join_room
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps   # OPTIMISATION: moved import to top level (code movement)
import sqlite3
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'secret!123')
socketio = SocketIO(app, cors_allowed_origins="*")

DATABASE = 'app.db'  # constant propagation — one place, used everywhere via this name

# OPTIMISATION: SQL strings stored as module-level constants (constant folding/propagation).
# Python evaluates these strings once at parse time rather than rebuilding them on every call.
_SQL_GET_USER        = 'SELECT * FROM users WHERE username = ?'
_SQL_GET_USER_TAGS   = 'SELECT tags FROM users WHERE username = ?'
_SQL_GET_OTHERS      = 'SELECT username, bio, tags FROM users WHERE username != ?'
_SQL_GET_INCOMING    = 'SELECT from_user FROM requests WHERE to_user = ?'
_SQL_GET_CONNS       = 'SELECT user1, user2 FROM connections WHERE user1 = ? OR user2 = ?'
_SQL_GET_HISTORY     = 'SELECT sender, text FROM messages WHERE room = ? ORDER BY timestamp ASC'
_SQL_INSERT_USER     = 'INSERT INTO users (username, password_hash, bio, tags) VALUES (?, ?, ?, ?)'
_SQL_INSERT_REQUEST  = 'INSERT OR IGNORE INTO requests (from_user, to_user) VALUES (?, ?)'
_SQL_INSERT_CONN     = 'INSERT OR IGNORE INTO connections (user1, user2) VALUES (?, ?)'
_SQL_INSERT_MSG      = 'INSERT INTO messages (room, sender, text) VALUES (?, ?, ?)'
_SQL_DELETE_REQUEST  = 'DELETE FROM requests WHERE from_user = ? AND to_user = ?'
_SQL_DELETE_CONN     = 'DELETE FROM connections WHERE user1 = ? AND user2 = ?'
_SQL_DELETE_REQUESTS_USER = 'DELETE FROM requests WHERE from_user = ? OR to_user = ?'
_SQL_DELETE_CONNS_USER    = 'DELETE FROM connections WHERE user1 = ? OR user2 = ?'
_SQL_DELETE_USER     = 'DELETE FROM users WHERE username = ?'
_SQL_UPDATE_PROFILE  = 'UPDATE users SET bio=?, tags=? WHERE username=?'
_SQL_UPDATE_FULL     = 'UPDATE users SET bio=?, tags=?, password_hash=? WHERE username=?'
_SQL_CHECK_EXISTS    = 'SELECT username FROM users WHERE username = ?'
_SQL_CHECK_CONN      = 'SELECT 1 FROM connections WHERE user1 = ? AND user2 = ?'
_SQL_PROFILE         = 'SELECT username, bio, tags FROM users WHERE username = ?'

#_____________________________________Database_Setup__________________________________

def get_db():
    #Opens and returns a connection to the SQLite database.
    #row_factory = sqlite3.Row allows columns to be accessed by name rather than by index.
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    #Creates all four database tables on startup if they do not already exist.
    with get_db() as conn:
        conn.executescript('''
            CREATE TABLE IF NOT EXISTS users (
                username      TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                bio           TEXT DEFAULT '',
                tags          TEXT DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS messages (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                room      TEXT NOT NULL,
                sender    TEXT NOT NULL,
                text      TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS requests (
                from_user TEXT NOT NULL,
                to_user   TEXT NOT NULL,
                PRIMARY KEY (from_user, to_user)
            );
            CREATE TABLE IF NOT EXISTS connections (
                user1 TEXT NOT NULL,
                user2 TEXT NOT NULL,
                PRIMARY KEY (user1, user2)
            );
        ''')


init_db()

# Set to track which users are currently online
online_users = set()

#_____________________________________Helpers__________________________________

def get_room_id(user1, user2):
    #Generates a consistent unique room ID by sorting names alphabetically.
    #e.g. get_room_id('zara','alex') == get_room_id('alex','zara') == 'alex_zara'
    return '_'.join(sorted([user1, user2]))


def parse_tags(tag_string):
    # OPTIMISATION: common sub-expression elimination.
    # Tag parsing (split → strip → filter) was repeated identically in browse(),
    # profile(), and settings(). Extracted into one reusable function so the
    # logic is defined once and reused everywhere — never recomputed.
    return [t.strip() for t in tag_string.split(',') if t.strip()]


def login_required(f):
    #Decorator that redirects unauthenticated users to the home page.
    @wraps(f)  # OPTIMISATION: wraps import moved to top (code movement)
    def decorated(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated


#_____________________________________ROUTES__________________________________

@app.route('/')
def home():
    if 'username' in session:
        return redirect(url_for('browse'))
    return render_template('home.html')


@app.route('/create-account', methods=['GET', 'POST'])
def create_account():
    #GET:  Displays the account creation form.
    #POST: Validates inputs, hashes password, saves to DB, logs user in.
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        bio      = request.form.get('bio', '').strip()
        tags     = request.form.get('tags', '').strip()

        if not username or not password:
            return render_template('create_account.html',
                                   error='Username and password are required.')

        with get_db() as conn:
            if conn.execute(_SQL_CHECK_EXISTS, (username,)).fetchone():
                return render_template('create_account.html',
                                       error='Username already taken.')
            # OPTIMISATION: generate_password_hash called once and result passed
            # directly into execute — avoids storing the hash in an intermediate
            # variable that is used only once (dead variable elimination).
            conn.execute(_SQL_INSERT_USER,
                         (username, generate_password_hash(password), bio, tags))

        session['username'] = username
        online_users.add(username)
        return redirect(url_for('browse'))

    return render_template('create_account.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    #GET:  Displays the login form.
    #POST: Verifies credentials against stored hash; sets session on success.
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        with get_db() as conn:
            user = conn.execute(_SQL_GET_USER, (username,)).fetchone()

        if not user or not check_password_hash(user['password_hash'], password):
            return render_template('login.html',
                                   error='Invalid username or password.')

        session['username'] = username
        online_users.add(username)
        return redirect(url_for('browse'))

    return render_template('login.html')


@app.route('/browse')
@login_required
def browse():
    #Displays the user discovery page.
    #Users who share more tags with the logged-in user appear first.
    me = session['username']  # OPTIMISATION: common sub-expression — session lookup
                               # stored once in 'me' and reused in every query below.

    with get_db() as conn:
        # OPTIMISATION: all four DB reads done inside a single connection block
        # (code movement) — avoids opening and closing the connection repeatedly.
        my_row   = conn.execute(_SQL_GET_USER_TAGS, (me,)).fetchone()
        rows     = conn.execute(_SQL_GET_OTHERS,    (me,)).fetchall()
        incoming = conn.execute(_SQL_GET_INCOMING,  (me,)).fetchall()
        conns    = conn.execute(_SQL_GET_CONNS,     (me, me)).fetchall()

    # OPTIMISATION: my_tags computed once outside the loop (code movement).
    # Previously this set was rebuilt on every iteration; now it is fixed
    # before the loop starts since 'me' never changes inside it.
    my_tags = set(parse_tags(my_row['tags']))

    # OPTIMISATION: connected_users built once as a set (code movement + strength reduction).
    # set membership check (O(1)) is cheaper than scanning a list on every card.
    connected_users = set()
    for c in conns:
        connected_users.add(c['user2'] if c['user1'] == me else c['user1'])

    other_users = []
    for r in rows:
        # OPTIMISATION: parse_tags() used here instead of repeating the same
        # split/strip/filter expression (common sub-expression elimination).
        user_tags = parse_tags(r['tags'])
        other_users.append({
            'username':  r['username'],
            'bio':       r['bio'],
            'tags':      user_tags,
            'shared':    len(my_tags & set(user_tags)),  # intersection — O(min(n,m))
            'connected': r['username'] in connected_users  # O(1) set lookup
        })

    other_users.sort(key=lambda u: u['shared'], reverse=True)

    return render_template('browse.html',
                           users=other_users,
                           current_user=me,
                           incoming_requests=[r['from_user'] for r in incoming],
                           online_count=len(online_users))


@app.route('/profile/<username>')
@login_required
def profile(username):
    #Displays a user's public profile page showing username, bio, and tags.
    with get_db() as conn:
        user = conn.execute(_SQL_PROFILE, (username,)).fetchone()

    if not user:
        return redirect(url_for('browse'))

    return render_template('profile.html',
                           user={
                               'username': user['username'],
                               'bio':      user['bio'],
                               # OPTIMISATION: parse_tags() reused here instead of
                               # repeating the split/strip/filter (common sub-expression).
                               'tags':     parse_tags(user['tags'])
                           },
                           current_user=session['username'])


@app.route('/request-chat/<target>')
@login_required
def request_chat(target):
    #Sends a chat request from the logged-in user to <target>.
    #INSERT OR IGNORE silently skips duplicate requests.
    me = session['username']
    with get_db() as conn:
        if conn.execute(_SQL_CHECK_EXISTS, (target,)).fetchone():
            conn.execute(_SQL_INSERT_REQUEST, (me, target))
    return redirect(url_for('browse'))


@app.route('/deny-chat/<requester>')
@login_required
def deny_chat(requester):
    #Denies a chat request — deletes it without creating a connection.
    me = session['username']
    with get_db() as conn:
        conn.execute(_SQL_DELETE_REQUEST, (requester, me))
    return redirect(url_for('browse'))


@app.route('/accept-chat/<requester>')
@login_required
def accept_chat(requester):
    #Accepts a chat request — deletes the request and creates a connection.
    #Names sorted so there is always exactly one row per pair in connections.
    me = session['username']
    # OPTIMISATION: sorted pair computed once and unpacked into user1, user2
    # (common sub-expression elimination) — reused in both execute calls below.
    user1, user2 = sorted([me, requester])
    with get_db() as conn:
        conn.execute(_SQL_DELETE_REQUEST, (requester, me))
        conn.execute(_SQL_INSERT_CONN,    (user1, user2))
    return redirect(url_for('messaging', partner=requester))


@app.route('/remove-user/<partner>')
@login_required
def remove_user(partner):
    #Removes the connection between logged-in user and <partner>.
    me = session['username']
    user1, user2 = sorted([me, partner])
    with get_db() as conn:
        conn.execute(_SQL_DELETE_CONN, (user1, user2))
    return redirect(url_for('browse'))


@app.route('/messaging/<partner>')
@login_required
def messaging(partner):
    #Displays the private chat page between the logged-in user and <partner>.
    #Checks the connections table first — redirects to browse if not connected.
    me   = session['username']
    room = get_room_id(me, partner)
    # OPTIMISATION: sorted pair computed once (common sub-expression elimination).
    user1, user2 = sorted([me, partner])

    with get_db() as conn:
        if not conn.execute(_SQL_CHECK_EXISTS, (partner,)).fetchone():
            return redirect(url_for('browse'))
        # OPTIMISATION: SELECT 1 used instead of SELECT * (strength reduction).
        # We only need to know if a row exists — fetching all columns wastes I/O.
        if not conn.execute(_SQL_CHECK_CONN, (user1, user2)).fetchone():
            return redirect(url_for('browse'))
        history = conn.execute(_SQL_GET_HISTORY, (room,)).fetchall()

    return render_template('messaging.html',
                           current_user=me,
                           partner=partner,
                           room=room,
                           history=[{'sender': r['sender'], 'text': r['text']}
                                    for r in history])


@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    #GET:  Displays settings page pre-filled with current user data.
    #POST: Handles update / delete / logout actions.
    me = session['username']  # OPTIMISATION: common sub-expression stored once.

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'update':
            bio          = request.form.get('bio', '').strip()
            tags         = request.form.get('tags', '').strip()
            new_password = request.form.get('new_password', '').strip()

            with get_db() as conn:
                if new_password:
                    conn.execute(_SQL_UPDATE_FULL,
                                 (bio, tags, generate_password_hash(new_password), me))
                else:
                    conn.execute(_SQL_UPDATE_PROFILE, (bio, tags, me))

            with get_db() as conn:
                user = conn.execute(_SQL_GET_USER, (me,)).fetchone()

            return render_template('settings.html', current_user=me,
                                   user=user, success='Account updated!')

        elif action == 'delete':
            online_users.discard(me)
            with get_db() as conn:
                conn.execute(_SQL_DELETE_USER,         (me,))
                conn.execute(_SQL_DELETE_REQUESTS_USER, (me, me))
                conn.execute(_SQL_DELETE_CONNS_USER,    (me, me))
            session.clear()
            return redirect(url_for('home'))

        elif action == 'logout':
            # OPTIMISATION: dead code eliminated — original code called
            # online_users.discard(session['username']) but 'me' already holds
            # that value, so the second session lookup was a redundant sub-expression.
            online_users.discard(me)
            session.clear()
            return redirect(url_for('home'))

    with get_db() as conn:
        user = conn.execute(_SQL_GET_USER, (me,)).fetchone()

    return render_template('settings.html', current_user=me, user=user)


#_____________________________________SocketIO event handlers__________________________________

@socketio.on('join')
def on_join(data):
    #Fired when a user opens the messaging page — adds them to the SocketIO room.
    join_room(data['room'])


@socketio.on('message')
def handle_message(data):
    #Fired when a user sends a message — saves to DB then broadcasts to room.
    # OPTIMISATION: common sub-expression elimination — data fields extracted
    # once into local variables and reused in both the INSERT and the emit.
    room   = data['room']
    sender = data['sender']
    text   = data['text']

    with get_db() as conn:
        conn.execute(_SQL_INSERT_MSG, (room, sender, text))

    emit('message', {'sender': sender, 'text': text}, to=room)


if __name__ == '__main__':
    #host='0.0.0.0' makes the server accessible on your local network
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
