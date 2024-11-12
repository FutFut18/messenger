from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import secrets
import string
import os
import bcrypt
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.urandom(84)

def hash_key(password):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode(), salt)
    return hashed.decode()

def check_key(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed.encode())

def generate_key(length):
    characters = string.ascii_letters + string.digits
    return ''.join(secrets.choice(characters) for _ in range(length))

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        action = request.form['action']
        if action == 'login':
            public_key = request.form.get("public_key")
            user_key = request.form.get('user_key')
            if user_key and public_key:
                try:
                    with open("data/users/" + public_key + "/hash.userdata") as f:
                        hash = f.read()
                    valid = check_key(user_key, hash)
                except:
                    valid = False
                if valid:
                    session['user_authenticated'] = True
                    session['public_key'] = public_key
                    return redirect(url_for('chats'))
                else:
                    message = "Неверный ключ входа или общий ключ!"
            else:
                message = "Введите ключ для входа."
        elif action == 'register':
            entry_key = generate_key(64)
            public_key = generate_key(12)
            directory_path = f"data/users/{public_key}"
            os.mkdir(directory_path)
            hashed_key = hash_key(entry_key)
            with open(directory_path + "/hash.userdata", "w") as f:
                f.write(hashed_key)
            #message = f"Сгенерирован ключ входа: {entry_key}, общий ключ: {public_key}"
        return render_template('index.html', key1 = public_key, key2 = entry_key)
    return render_template('index.html')

@app.route('/chats', methods=["GET", "POST"])
def chats():
    if 'user_authenticated' not in session or not session['user_authenticated']:
        return redirect(url_for('index'))
    message = ""
    if request.method == "POST":
        action = request.form['action']
        if action == 'logout':
            return redirect(url_for('logout'))
        if action == 'message':
            username = request.form.get('public_key')
            if username == session['public_key']:
                message = "Это ваш публичный ключ!"
            elif os.path.isdir(f"data/users/{username}"):
                chatdir = f"data/users/{username}/chats"
                if not os.path.isdir(chatdir):
                    os.mkdir(chatdir)
                user_chat_dir = f"data/users/{username}/chats/{session['public_key']}"
                if not os.path.isdir(user_chat_dir):
                    os.mkdir(user_chat_dir)
                if not os.path.isdir(f"data/users/{session['public_key']}/chats/"):
                    os.mkdir(f"data/users/{session['public_key']}/chats")
                if not os.path.isdir(f"data/users/{session['public_key']}/chats/{username}"):
                    os.mkdir(f"data/users/{session['public_key']}/chats/{username}")
                with open(f"data/users/{session['public_key']}/chats/{username}/messages.txt", "w") as file:
                    file.write("")
                message = "Чат с этим пользователем успешно создан или открыт."
                session['open_chat'] = username
                return redirect(url_for('messages'))
            else:
                message = "Введен неверный публичный ключ."
    return render_template('chats.html', message=message)

@app.route('/nickname', methods=["GET", "POST"])
def nickname():
    if 'user_authenticated' not in session or not session['user_authenticated']:
        return redirect(url_for('index'))
    message = ""
    if request.method == "POST":
        action = request.form['action']
        if action == 'logout':
            return redirect(url_for('logout'))
        if action == 'change':
            nick = request.form.get('nick')
            if nick == session['public_key']:
                message = "Это ваш публичный ключ!"
            else:
                directory = f"data/users/{session['public_key']}"
                if not os.path.isdir(directory):
                    return redirect(url_for('index'))
                else:
                    file = f"{directory}/nick.userdata"
                    if not os.path.isfile(file):
                        with open(file, "w") as userdata:
                            userdata.write("")
                    filenns = "data/nns.serverdata"
                    if not os.path.isfile(filenns):
                        with open(filenns, "w") as nns:
                            nns.write("")
                    with open(file, "w") as userdata:
                        userdata.write(nick)
                    with open(filenns, "a") as nns:
                        nns.write(f"{session['public_key']} ||| {nick}\n")

    return render_template('nickname.html', message=message)

@app.route('/messages', methods=["GET", "POST"])
def messages():
    if 'user_authenticated' not in session or not session['user_authenticated']:
        return redirect(url_for('index'))

    open_chat = session.get('open_chat', None)
    if not open_chat:
        return redirect(url_for('chats'))

    chat_file_path = f"data/users/{open_chat}/chats/{session['public_key']}/messages.txt"
    os.makedirs(os.path.dirname(chat_file_path), exist_ok=True)
    chat_file_path1 = f"data/users/{session['public_key']}/chats/{open_chat}/messages.txt"

    messages_history = []
    if os.path.exists(chat_file_path):
        with open(chat_file_path, 'r', encoding='utf-8') as file:
            messages_history = file.readlines()

    if request.method == "POST":
        action = request.form['action']
        if action == 'send_message':
            message_text = request.form.get('message_text')
            if message_text:
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                new_message = f"{session['public_key']} ({timestamp}): {message_text}\n"
                with open(chat_file_path, 'a', encoding='utf-8') as file:
                    file.write(new_message)
                with open(chat_file_path1, 'a', encoding='utf-8') as file:
                    file.write(new_message)
                messages_history.append(new_message)

    return render_template('messages.html', messages=messages_history)


@app.route('/poll_messages')
def poll_messages():
    if 'user_authenticated' not in session or not session['user_authenticated']:
        return jsonify({"status": "unauthorized"}), 403

    open_chat = session.get('open_chat', None)
    if not open_chat:
        return jsonify({"status": "no_chat"}), 400

    chat_file_path = f"data/users/{open_chat}/chats/{session['public_key']}/messages.txt"

    if os.path.exists(chat_file_path):
        with open(chat_file_path, 'r', encoding='utf-8') as file:
            messages = file.readlines()

        return jsonify({"messages": messages})

    return jsonify({"messages": []})

@app.route('/logout')
def logout():
    session.pop('user_authenticated', None)
    session.pop('public_key', None)
    session.pop('open_chat', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=50001, debug=True)