#!/usr/bin/env python3


from base64 import b64decode, b64encode
from random import choice
from os import environ, mkdir, rename
from os.path import isfile, join
from re import compile as re_compile
from shutil import rmtree
from string import ascii_letters, digits

from flask import Flask, escape, redirect, request, url_for
from nacl.secret import SecretBox


app = Flask(__name__)

DATA = environ.get('FLUESTERFIX_DATA', '/tmp')
SECRET_KEY = environ['FLUESTERFIX_KEY']
SID_LEN = 32
SID_VALIDATOR = re_compile(f'^[A-Za-z0-9]{{{SID_LEN}}}$')


def decrypt(msg):
    box = SecretBox(b64decode(SECRET_KEY))
    return box.decrypt(msg).decode('UTF-8')


def encrypt(msg):
    box = SecretBox(b64decode(SECRET_KEY))
    return box.encrypt(msg.encode('UTF-8'))


def generate_sid():
    pool = ascii_letters + digits
    sid = ''
    for i in range(SID_LEN):
        sid += choice(pool)
    return sid


def html(body):
    return f'''<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Share a secret</title>
        <link rel="stylesheet" href="{ url_for('static', filename='style.css') }" type="text/css">
        <script src="{ url_for('static', filename='clipboard.js') }"></script>
    </head>
    <body>
        {body}
    </body>
</html>'''


def retrieve(sid, password=None):
    # Try to rename this sid's directory. This is an atomic operation on
    # POSIX file systems, meaning two concurrent requests cannot rename
    # the same directory -- for one of them, it will look like the
    # source directory does not exist. This also implicitly covers the
    # case where we try to retrieve an invalid sid.
    locked_sid = sid + '_locked'
    try:
        rename(join(DATA, sid), join(DATA, locked_sid))
    except OSError:
        return None

    # If the secret requires a password, check it now. This is done
    # after the secret has been locked. This will remove the secret if
    # a wrong password is supplied, thus removing any ability to try
    # brute-forcing a password, because the allowed number of attempts
    # is limited to 1 (one).
    passwordfile = join(DATA, locked_sid, 'password')
    if password and isfile(passwordfile):
        with open(passwordfile, 'rb') as fp:
            password_bytes = fp.read()

        if password != decrypt(password_bytes):
            rmtree(join(DATA, locked_sid))
            return None

    # Now that we have "locked" this sid, we can safely read it and then
    # destroy it.
    with open(join(DATA, locked_sid, 'secret'), 'rb') as fp:
        secret_bytes = fp.read()
    rmtree(join(DATA, locked_sid))

    return decrypt(secret_bytes)


def store(secret, password=None):
    while True:
        try:
            # Again, mkdir is an atomic operation on POSIX file systems.
            # Two concurrent requests cannot store data into the same
            # directory.
            sid = generate_sid()
            mkdir(join(DATA, sid))
            break
        except FileExistsError:
            continue

    if password:
        with open(join(DATA, sid, 'password'), 'wb') as fp:
            fp.write(encrypt(password))

    with open(join(DATA, sid, 'secret'), 'wb') as fp:
        fp.write(encrypt(secret))

    return sid


def validate_sid(sid):
    assert SID_VALIDATOR.search(sid) is not None


@app.route('/')
def index():
    return html('''
        <h1>Share a new secret</h1>
        <p>Enter your text into the box below. Once you hit the button,
           you will get a link that you can send to someone else. That
           link can only be used once.</p>
        <form action="/new" method="post">
            <input type="password" name="password"
             placeholder="If you want to secure the secret using an additional password, enter it here.">
            <textarea name="data"></textarea>
            <input type="submit" value="&#x1f517; Create link">
        </form>
    ''')


@app.route('/new', methods=['POST'])
def new():
    try:
        form = request.form.to_dict()
        secret = form['data']
        password = form['password']
    except:
        return 'Garbage'

    if len(secret.strip()) <= 0:
        return redirect(url_for('index'))

    sid = store(secret, password)
    scheme = request.headers.get('x-forwarded-proto', 'http')
    host = request.headers.get('x-forwarded-host', request.headers['host'])
    sid_url = f'{scheme}://{host}/get/{sid}'
    return html(f'''
        <h1>Share this link</h1>
        <p>Send <a href="{sid_url}">this link</a> to someone else:</p>
        <p><input id="copytarget" type="text" value="{sid_url}"></p>
        <p><span class="button" onclick="copy()">&#x1f4cb; Copy to clipboard</span></p>
    '''), 201


@app.route('/get/<sid>')
def get(sid):
    validate_sid(sid)
    # FIXME Without that hidden field, lynx insists on doing GET. Is
    # that a bug in lynx or is it invalid to POST empty forms?
    form_field = '<input name="compat" type="hidden" value="lynx needs this">'
    if isfile(join(DATA, sid, 'password')):
        form_field = (
            '<p><label for="password">This secret is protected by a password. '
            'Please enter it here:</label></p>'
            '<input type="password" name="password" id="password">'
            '<p>Be careful! If you enter a wrong password, the secret '
            'will be gone forever.</p>'
        )
    return html(f'''
        <h1>Reveal this secret?</h1>
        <p>You can only do this once.</p>
        <form action="/reveal/{sid}" method="post">
            {form_field}
            <input type="submit" value="&#x1f50d; Reveal the secret">
        </form>
    ''')


@app.route('/reveal/<sid>', methods=['POST'])
def reveal(sid):
    validate_sid(sid)
    try:
        password = request.form.to_dict()['password']
    except:
        password = None
    secret = retrieve(sid, password)
    if secret is None:
        return html(f'''
            <h1>Error</h1>
            <p>This secret could not be retrieved.</p>
        '''), 404
    else:
        # Show all lines, if possible. Never show more than 100, though.
        # CSS also sets a min-height for this.
        lines = min(len(secret.split('\n')), 100)
        return html(f'''
            <h1>Secret</h1>
            <p>Here’s your secret. It is no longer accessible through
               the link, so copy it <em>now</em>.</p>
            <textarea rows="{lines}" id="copytarget">{escape(secret)}</textarea>
            <p><span class="button" onclick="copy()">&#x1f4cb; Copy to clipboard</span></p>
        '''), 410


if __name__ == '__main__':
    app.run(host='::')
