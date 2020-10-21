#!/usr/bin/env python3


from base64 import b64decode, b64encode
from random import choice
from os import environ, mkdir, rename
from os.path import join
from re import compile as re_compile
from shutil import rmtree
from string import ascii_letters, digits
from subprocess import run

from flask import Flask, escape, redirect, request, url_for
from nacl.secret import SecretBox
from nacl.utils import random


app = Flask(__name__)

DATA = environ.get('FLUESTERFIX_DATA', '/tmp')
SID_LEN = 4
SID_VALIDATOR = re_compile(f'^[A-Za-z0-9]{{{SID_LEN}}}$')

# I wish there were enums in Python.
ALREADY_REVEALED = 0
WRONG_KEY = 1
OK = 2


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


def retrieve(sid, key):
    # Try to rename this sid's directory. This is an atomic operation on
    # POSIX file systems, meaning two concurrent requests cannot rename
    # the same directory -- for one of them, it will look like the
    # source directory does not exist. This also implicitly covers the
    # case where we try to retrieve an invalid sid.
    locked_sid = sid + '_locked'
    try:
        rename(join(DATA, sid), join(DATA, locked_sid))
    except OSError:
        return None, ALREADY_REVEALED

    # Now that we have "locked" this sid, we can safely read it and then
    # destroy it.
    with open(join(DATA, locked_sid, 'secret'), 'rb') as fp:
        secret_bytes = fp.read()
    run(['/usr/bin/shred', join(DATA, locked_sid, 'secret')])
    rmtree(join(DATA, locked_sid))

    key_bytes = b64decode(key.replace('_', '/').encode('ASCII'))
    try:
        box = SecretBox(key_bytes)
        decrypted_bytes = box.decrypt(secret_bytes)
    except:
        return None, WRONG_KEY
    return decrypted_bytes.decode('UTF-8'), OK


def store(secret):
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

    key = random(SecretBox.KEY_SIZE)
    box = SecretBox(key)

    with open(join(DATA, sid, 'secret'), 'wb') as fp:
        fp.write(box.encrypt(secret.encode('UTF-8')))

    return sid, str(b64encode(key), 'ASCII').replace('/', '_')


def validate_key(key):
    # It's random bytes, there's not a lot to validate, except for the
    # length (32 bytes encoded using base64).
    assert len(key) == 44


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
            <textarea name="data"></textarea>
            <input type="submit" value="&#x1f517; Create link">
        </form>
    ''')


@app.route('/new', methods=['POST'])
def new():
    try:
        secret = request.form.to_dict()['data']
    except:
        return 'Garbage'

    if len(secret.strip()) <= 0:
        return redirect(url_for('index'))

    sid, key = store(secret)
    scheme = request.headers.get('x-forwarded-proto', 'http')
    host = request.headers.get('x-forwarded-host', request.headers['host'])
    sid_url = f'{scheme}://{host}/get/{sid}/{key}'
    return html(f'''
        <h1>Share this link</h1>
        <p>Send this link to someone else. <em>It will be valid for 7 days.</em></p>
        <p><input id="copytarget" type="text" value="{sid_url}"></p>
        <p><span class="button" onclick="copy()">&#x1f4cb; Copy to clipboard</span></p>
    '''), 201


@app.route('/get/<sid>/<key>')
def get(sid, key):
    validate_key(key)
    validate_sid(sid)
    # FIXME Without that hidden field, lynx insists on doing GET. Is
    # that a bug in lynx or is it invalid to POST empty forms?
    return html(f'''
        <h1>Reveal this secret?</h1>
        <p>You can only do this once.</p>
        <form action="/reveal/{sid}/{key}" method="post">
            <input name="compat" type="hidden" value="lynx needs this">
            <input type="submit" value="&#x1f50d; Reveal the secret">
        </form>
    ''')


@app.route('/reveal/<sid>/<key>', methods=['POST'])
def reveal(sid, key):
    validate_key(key)
    validate_sid(sid)
    secret, status = retrieve(sid, key)
    if status == ALREADY_REVEALED:
        return html(f'''
            <h1>Error</h1>
            <p>This secret has already been revealed.</p>
        '''), 404
    elif status == WRONG_KEY:
        # Provide a dedicated error message if a wrong key was used.
        # This tries to avoid confusion of users: They will now know
        # that they made a mistake while copying the URL (or a
        # consultant can tell them that). Since the secret has been
        # destroyed, there is no risk of being brute forced. (If the
        # secret lived on, an attacker might try again and again.)
        return html(f'''
            <h1>Error</h1>
            <p>Wrong key. Secret has been destroyed.</p>
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
