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

TRANS = {
    'en': {
        'already revealed': 'This secret has already been revealed.',
        'clip': 'Copy to clipboard',
        'create link': 'Create link',
        'error': 'Error',
        'only once': 'You can only do this once.',
        'reveal!': 'Reveal the secret',
        'reveal?': 'Reveal this secret?',
        'secret': 'Secret',
        'share': 'Share a secret',
        'share new': 'Share a new secret',
        'share this': 'Share this link',
        'share this desc': 'Send this link to someone else. <em>It will '
                           'be valid for 7 days.</em>',
        'welcome desc': 'Enter your text into the box below. Once you '
                        'hit the button, you will get a link that you '
                        'can send to someone else. That link can only '
                        'be used once.',
        'wrong key': 'Wrong key. Secret has been destroyed.',
        'your secret': 'Here’s your secret. It is no longer accessible '
                       'through the link, so copy it <em>now</em>.',
    },
    'de': {
        'already revealed': 'Die vertraulichen Daten wurden bereits '
                            'abgerufen.',
        'clip': 'In die Zwischenablage kopieren',
        'create link': 'Link erzeugen',
        'error': 'Fehler',
        'only once': 'Sie können diesen Vorgang nur <em>einmalig</em> '
                     'durchführen.',
        'reveal!': 'Vertrauliche Daten anzeigen',
        'reveal?': 'Vertrauliche Daten anzeigen?',
        'secret': 'Vertrauliche Daten',
        'share': 'Vertrauliche Daten weitergeben',
        'share new': 'Neue vertrauliche Daten',
        'share this': 'Geben Sie diesen Link weiter',
        'share this desc': 'Geben Sie den folgenden Link weiter. <em>Er '
                           'ist nur für 7 Tage gültig.</em>',
        'welcome desc': 'Geben Sie Ihre vertraulichen Daten in die '
                        'Textbox unten ein. Sobald Sie den Knopf '
                        'betätigen, erhalten Sie einen Link, den Sie '
                        'weitergeben können. Dieser Link kann nur ein '
                        'einziges Mal abgerufen werden.',
        'wrong key': 'Falscher Schlüssel. Daten wurden gelöscht.',
        'your secret': 'Untenstehend finden Sie die angefragten '
                       'vertraulichen Daten. Von nun an ist es nicht '
                       'mehr möglich, diesen Link zu verwenden. Sie '
                       'sollten die Daten also <em>jetzt</em> sichern.',
    },
}


def _(msg):
    return TRANS[get_lang()].get(msg, msg)


def get_lang():
    selected = request.accept_languages.best_match(TRANS.keys())
    if selected:
        return selected
    return 'en'


def generate_sid():
    pool = ascii_letters + digits
    sid = ''
    for i in range(SID_LEN):
        sid += choice(pool)
    return sid


def html(body):
    return f'''<!DOCTYPE html>
<html lang="{get_lang()}">
    <head>
        <meta charset="UTF-8">
        <title>{_('share')}</title>
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

    # Restore padding. (No point in using something like a while loop
    # here, we checked for an explicit length earlier.)
    key += '='
    key = key.replace('_', '/')
    key_bytes = b64decode(key.encode('ASCII'))
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

    key_bytes = random(SecretBox.KEY_SIZE)
    box = SecretBox(key_bytes)

    with open(join(DATA, sid, 'secret'), 'wb') as fp:
        fp.write(box.encrypt(secret.encode('UTF-8')))

    # Turn key into base64 and remove padding, because it has the
    # potential of confusing users. ("Is this part of the URL?")
    key = str(b64encode(key_bytes), 'ASCII')
    key = key.replace('/', '_')
    key = key.rstrip('=')

    return sid, key


def validate_key(key):
    # It's random bytes, there's not a lot to validate, except for the
    # length (32 bytes encoded using base64 - minus the rightmost '=').
    assert len(key) == 44 - 1


def validate_sid(sid):
    assert SID_VALIDATOR.search(sid) is not None


@app.route('/')
def index():
    return html(f'''
        <h1>{_('share new')}</h1>
        <p>{_('welcome desc')}</p>
        <form action="/new" method="post">
            <textarea name="data"></textarea>
            <input type="submit" value="&#x1f517; {_('create link')}">
        </form>
    ''')


@app.route('/new', methods=['POST'])
def new():
    try:
        secret = request.form.to_dict()['data']
    except:
        return 'Garbage', 400

    if len(secret.strip()) <= 0:
        return redirect(url_for('index'))

    sid, key = store(secret)
    scheme = request.headers.get('x-forwarded-proto', 'http')
    host = request.headers.get('x-forwarded-host', request.headers['host'])
    sid_url = f'{scheme}://{host}/get/{sid}/{key}'
    return html(f'''
        <h1>{_('share this')}</h1>
        <p>{_('share this desc')}</p>
        <p><input id="copytarget" type="text" value="{sid_url}"></p>
        <p><span class="button" onclick="copy()">&#x1f4cb; {_('clip')}</span></p>
    '''), 201


@app.route('/get/<sid>/<key>')
def get(sid, key):
    validate_key(key)
    validate_sid(sid)
    # FIXME Without that hidden field, lynx insists on doing GET. Is
    # that a bug in lynx or is it invalid to POST empty forms?
    return html(f'''
        <h1>{_('reveal?')}</h1>
        <p>{_('only once')}</p>
        <form action="/reveal/{sid}/{key}" method="post">
            <input name="compat" type="hidden" value="lynx needs this">
            <input type="submit" value="&#x1f50d; {_('reveal!')}">
        </form>
    ''')


@app.route('/reveal/<sid>/<key>', methods=['POST'])
def reveal(sid, key):
    validate_key(key)
    validate_sid(sid)
    secret, status = retrieve(sid, key)
    if status == ALREADY_REVEALED:
        return html(f'''
            <h1>{_('error')}</h1>
            <p>{_('already revealed')}</p>
        '''), 404
    elif status == WRONG_KEY:
        # Provide a dedicated error message if a wrong key was used.
        # This tries to avoid confusion of users: They will now know
        # that they made a mistake while copying the URL (or a
        # consultant can tell them that). Since the secret has been
        # destroyed, there is no risk of being brute forced. (If the
        # secret lived on, an attacker might try again and again.)
        return html(f'''
            <h1>{_('error')}</h1>
            <p>{_('wrong key')}</p>
        '''), 404
    else:
        # Show all lines, if possible. Never show more than 100, though.
        # CSS also sets a min-height for this.
        lines = min(len(secret.split('\n')), 100)
        return html(f'''
            <h1>{_('secret')}</h1>
            <p>{_('your secret')}</p>
            <textarea rows="{lines}" id="copytarget">{escape(secret)}</textarea>
            <p><span class="button" onclick="copy()">&#x1f4cb; {_('clip')}</span></p>
        '''), 410


if __name__ == '__main__':
    app.run(host='::')
