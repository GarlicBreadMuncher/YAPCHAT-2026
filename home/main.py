from flask import Flask, render_template, request, redirect, url_for, session
from flask_socketio import SocketIO, emit, join_room
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
from cryptography.fernet import Fernet

# Generate once and hardcode the result — if you lose this key
# all messages become permanently unreadable
ENCRYPTION_KEY = b'XHhnc_KrXpXi0AaZ8E87yjJ--ZJp1adMd34A7UmGHJs='
fernet = Fernet(ENCRYPTION_KEY)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'secret!123') #to cryptographically sign data. This prevents attackers from tampering with sensitive information.
socketio = SocketIO(app, cors_allowed_origins="*")

DATABASE = 'app.db'  # name of the SQLite database file stored on disk

#_____________________________________Database_Setup__________________________________

def get_db():
    
    #Opens and returns a connection to the SQLite database.
    #row_factory = sqlite3.Row allows columns to be accessed by name rather than by index (e.g. user['username']) instead of (e.g. user[0]).
    
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():

    #Creates the three database tables upon server startup if they do not already exist.
    #Tables are called once automatically when the server/program starts.

    #Tables:
       #users: stores account info (username, hashed password, bio, tags)
       #messages: stores every chat message with its room, sender, and timestamp
       #requests: stores pending chat requests between users

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


#Runs init_db on startup so tables are always ready
init_db()

#Set to track which users are currently online
online_users = set()

#_____________________________________room ID + access prevention unless logged in FUNCTIONS__________________________________

def get_room_id(user1, user2):

                                             
    return '_'.join(sorted([user1, user2])) #Generates a consistent, unique room ID for two users. 


def login_required(f):
    
    #Decorator that protects a route from being accessed when not logged in.
    #Wraps any route function — if no 'username' exists in the session then the user is redirected to the home page instead of loading the page.

    from functools import wraps
    @wraps(f)
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
    
    #GET:  Displays the account creation form (create_account.html).
    #POST: Reads submitted form data, validates it, hashes the password, saves the new user to the database, and logs them in via session.

    if request.method == 'POST':
        # Read and clean form inputs
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        bio      = request.form.get('bio', '').strip()
        tags     = request.form.get('tags', '').strip()

        # Validate: required fields must not be empty
        if not username or not password:
            return render_template('create_account.html',
                                   error='Username and password are required.')

        with get_db() as conn:
            # Check if the username is already taken
            existing = conn.execute(
                'SELECT username FROM users WHERE username = ?', (username,)
            ).fetchone()

            if existing:
                return render_template('create_account.html',
                                       error='Username already taken.')

            # Hash the password before storing — never store plain text passwords
            conn.execute(
                'INSERT INTO users (username, password_hash, bio, tags) VALUES (?, ?, ?, ?)',
                (username, generate_password_hash(password), bio, tags)
            )

        # Log the new user in by storing their username in the session
        session['username'] = username
        return redirect(url_for('browse'))

    return render_template('create_account.html')

#_____________________________________Login_Page__________________________________

@app.route('/login', methods=['GET', 'POST']) 
def login():
    
    #GET:  Displays the login form (login.html).
    #POST: Reads submitted credentials, looks up the user in the database, and verifies the password against the stored hash.
          #On success: stores username in session and redirects to browse.
          #On failure: re-renders the login page with an error message.
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        with get_db() as conn:
            #Fetch the user row matching the submitted username
            user = conn.execute(
                'SELECT * FROM users WHERE username = ?', (username,)
            ).fetchone()

        #check_password_hash compares the submitted password against the stored hash
        if not user or not check_password_hash(user['password_hash'], password):
            return render_template('login.html',
                                   error='Invalid username or password.')


        session['username'] = username
        online_users.add(username)  #When Users login, it marks them online.
        return redirect(url_for('browse'))

    return render_template('login.html')

#_____________________________________BROWSE__________________________________
@app.route('/browse') 
@login_required
def browse():

    #Displays the user discovery page
    #Fetches all registered users EXCEPT the logged-in user, and fetches any pending incoming message requests for the logged-in user.
    #Tags are stored as a comma-separated string and split into a list here before being passed to the template.


    me = session['username']

    with get_db() as conn:

        #Get the logged-in user's own tags
        my_row = conn.execute(
            'SELECT tags FROM users WHERE username = ?', (me,)
        ).fetchone()

        #Get every user except the currently logged-in one
        rows = conn.execute(
            'SELECT username, bio, tags FROM users WHERE username != ?', (me,)
        ).fetchall()

        #Get the list of users who have sent a chat request to the logged-in user
        incoming = conn.execute(
            'SELECT from_user FROM requests WHERE to_user = ?', (me,)
        ).fetchall()

    #Convert the logged-in user's tags into a set for easy comparison
    my_tags = set(t.strip() for t in my_row['tags'].split(',') if t.strip())

    #Build a set of usernames the logged-in user is already connected to
    with get_db() as conn:
        connections = conn.execute(
            'SELECT user1, user2 FROM connections WHERE user1 = ? OR user2 = ?',
            (me, me)
        ).fetchall()

    connected_users = set()
    for c in connections:
        other = c['user2'] if c['user1'] == me else c['user1']
        connected_users.add(other)

    other_users = []
    for r in rows:
        user_tags = [t.strip() for t in r['tags'].split(',') if t.strip()]

        #Count how many tags this user shares with the logged-in user
        shared = len(my_tags & set(user_tags))

    #Convert the raw database rows into plain dicts for the template
    #Split the tags string back into a list (e.g. 'music,art' -> ['music', 'art'])
    
        other_users.append({
            'username':  r['username'],
            'bio':       r['bio'],
            'tags':      user_tags,
            'shared':    shared,                              #used for sorting, not displayed
            'connected': r['username'] in connected_users    #True if already connected, False if not
        })

    # Sort by number of shared tags — highest first
    other_users.sort(key=lambda u: u['shared'], reverse=True)

    incoming_requests = [r['from_user'] for r in incoming]

    return render_template('browse.html', users=other_users,                        
                           current_user=me, incoming_requests=incoming_requests,
                           online_count=len(online_users))                          #displays how many users online/logged in currently.

@app.route('/profile/<username>') #____________________PROFILE_PAGE________________________
@login_required
def profile(username):
    
    #Displays a user's public profile page.
    #Shows their username, bio, and tags.
    
    with get_db() as conn:
        user = conn.execute(
            'SELECT username, bio, tags FROM users WHERE username = ?', (username,)
        ).fetchone()

    if not user:
        return redirect(url_for('browse'))

    user_data = {
        'username': user['username'],
        'bio':      user['bio'],
        'tags':     [t.strip() for t in user['tags'].split(',') if t.strip()]
    }

    return render_template('profile.html', user=user_data,
                           current_user=session['username'])

@app.route('/request-chat/<target>')#_______________________REQUEST_CHAT________________________________
@login_required
def request_chat(target):

    #Sends a chat request from the logged-in user to <target>.

    #INSERT OR IGNORE means if a request already exists between these two users it is silently ignored (no duplicate requests).
    #Redirects back to the browse page after sending request.

    me = session['username']

    with get_db() as conn:
        #Verify the target user actually exists before inserting a request
        user_exists = conn.execute(
            'SELECT username FROM users WHERE username = ?', (target,)
        ).fetchone()

        if user_exists:
            conn.execute(
                'INSERT OR IGNORE INTO requests (from_user, to_user) VALUES (?, ?)',
                (me, target)
            )

    return redirect(url_for('browse'))


@app.route('/accept-chat/<requester>')
@login_required
def accept_chat(requester):

    #Accepts an incoming chat request from <requester>.
    #Deletes the request row from the database, creates a connection between the two users,
    #then redirects to the private messaging page.
    #INSERT OR IGNORE prevents duplicate connections being created.

    me = session['username']

    with get_db() as conn:
        #Deletes the request now that it has been accepted
        conn.execute(
            'DELETE FROM requests WHERE from_user = ? AND to_user = ?',
            (requester, me)
        )
        #Sort names alphabetically so there is only ever one row per pair
        user1, user2 = sorted([me, requester])
        conn.execute(
            'INSERT OR IGNORE INTO connections (user1, user2) VALUES (?, ?)',
            (user1, user2)
        )

    return redirect(url_for('messaging', partner=requester))


@app.route('/deny-chat/<requester>')
@login_required
def deny_chat(requester):

    #Denies an incoming chat request from <requester>.
    #Deletes the request from the database WITHOUT opening a chat or creating a connection.
    #Redirects back to the browse page.

    me = session['username']
    with get_db() as conn:
        conn.execute(
            'DELETE FROM requests WHERE from_user = ? AND to_user = ?',
            (requester, me)
        )
    return redirect(url_for('browse'))


@app.route('/remove-user/<partner>')
@login_required
def remove_user(partner):

    #Removes the connection between the logged-in user and <partner>.
    #Deletes the connection row from the database so neither user can access
    #the chat with the other anymore.
    #Redirects back to the browse page.

    me = session['username']
    user1, user2 = sorted([me, partner])  #sort so the pair always matches the stored row
    with get_db() as conn:
        conn.execute(
            'DELETE FROM connections WHERE user1 = ? AND user2 = ?',
            (user1, user2)
        )
    return redirect(url_for('browse'))


@app.route('/messaging/<partner>')
@login_required
def messaging(partner):

                            #Displays the private chat page (messaging.html) between the logged-in user and <partner>.
                            #Loads the full message history for this room from the database so previous messages appear when the page loads.
                            #Messages are ordered oldest-first (ASC) so the chat reads top to bottom.
                            #Now checks the connections table to verify the two users are connected before allowing access.
                            #Redirects to browse if <partner> does not exist or if the two users are not connected.

    me     = session['username']
    room   = get_room_id(me, partner)  #consistent room key for this pair of users
    user1, user2 = sorted([me, partner])

    with get_db() as conn:
                            #Checks that the partner is a real registered user
        partner_exists = conn.execute(
            'SELECT username FROM users WHERE username = ?', (partner,)
        ).fetchone()

        if not partner_exists:
            return redirect(url_for('browse'))

                            #Check a connection exists between these two users
        connected = conn.execute(
            'SELECT * FROM connections WHERE user1 = ? AND user2 = ?',
            (user1, user2)
        ).fetchone()

        if not connected:
            return redirect(url_for('browse'))

                            #Loads all past messages for this room. Oldest to newest
        history = conn.execute(
            'SELECT sender, text FROM messages WHERE room = ? ORDER BY timestamp ASC',
            (room,)
        ).fetchall()


                            #Convert to plain dicts for the template
    history = [{'sender': r['sender'], 'text': r['text']} for r in history]

    return render_template('messaging.html', current_user=me,
                           partner=partner, room=room, history=history)


@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    
        #GET:  Displays the settings page (settings.html) pre-filled with the current user's bio and tags.

        #POST: Handles three possible actions submitted via a hidden form field:

        #update: Updates the user's bio, tags, and optionally their password. Password is only updated if a new one was typed in.

        #delete: Permanently deletes the user's account and all their associated requests from the database, clears the session and redirects to the home page.

        #Logout: Clears the session and redirects to the home page.
    
    me = session['username']

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'update':
            bio          = request.form.get('bio', '').strip()
            tags         = request.form.get('tags', '').strip()
            new_password = request.form.get('new_password', '').strip()

            with get_db() as conn:
                if new_password:
                    #update bio, tags, and hash + store the new password
                    conn.execute(
                        'UPDATE users SET bio=?, tags=?, password_hash=? WHERE username=?',
                        (bio, tags, generate_password_hash(new_password), me)
                    )
                else:
                    #Only update bio and tags, leave password unchanged
                    conn.execute(
                        'UPDATE users SET bio=?, tags=? WHERE username=?',
                        (bio, tags, me)
                    )

            #Re-fetch updated user data to display the success message
            with get_db() as conn:
                user = conn.execute(
                    'SELECT * FROM users WHERE username = ?', (me,)
                ).fetchone()

            return render_template('settings.html', current_user=me,
                                   user=user, success='Account updated!')

        elif action == 'delete':
            online_users.discard(me)  #remove from online set on account deletion
            with get_db() as conn:
                conn.execute('DELETE FROM users WHERE username = ?', (me,))         #deletes user account from database + returns them to homepage after.
                conn.execute(
                    'DELETE FROM requests WHERE from_user = ? OR to_user = ?',
                    (me, me)
                )
                conn.execute(
                    'DELETE FROM connections WHERE user1 = ? OR user2 = ?',
                    (me, me)
                )
            session.clear()
            return redirect(url_for('home'))

        elif action == 'logout':
            online_users.discard(session['username'])  #removes from online set (less users online)
            session.clear()                            #clears the session (logs out user)
            return redirect(url_for('home'))

        

    #GET request: load current user data to pre-fill the form
    with get_db() as conn:
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?', (me,)
        ).fetchone()

    return render_template('settings.html', current_user=me, user=user)


#_____________________________________Socket IO event handlers__________________________________

@socketio.on('join')
def on_join(data):
    
    #SocketIO event: fired when a user opens the messaging page. Adds the user's socket connection to the specified room so they will receive messages broadcast to that room.

    join_room(data['room'])


@socketio.on('message')
def handle_message(data):
    room   = data['room']
    sender = data['sender']
    text   = data['text']

    # Encrypt the message before storing
    encrypted_text = fernet.encrypt(text.encode()).decode()

    with get_db() as conn:
        conn.execute(_SQL_INSERT_MSG, (room, sender, encrypted_text))

    emit('message', {'sender': sender, 'text': text}, to=room)


if __name__ == '__main__':
    #host= YOUR IPV4 ADDRESS. (IN CMD PROMT TYPE "ipconfig" replace, COPY AND PASTE YOUR IPV4 INTO THE host
    #Change to host='localhost' to restrict access to this machine only
    socketio.run(app, host='10.0.0.5', port=5000, debug=True)
