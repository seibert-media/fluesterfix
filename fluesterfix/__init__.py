#!/usr/bin/env python3


from base64 import b64decode, b64encode
from random import choice
from os import environ, mkdir, rename
from os.path import isdir, isfile, join
from re import compile as re_compile
from shutil import rmtree
from string import ascii_letters, digits
from subprocess import run
import unicodedata
from urllib.parse import quote

from flask import Flask, jsonify, make_response, redirect, request, url_for
from markupsafe import escape
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
        'already revealed': '<p>This secret has already been '
                            'revealed.</p><p>If you are the recipient '
                            'of this secret, but haven\'t revealed it, '
                            'you should inform the creator of the '
                            'secret about a potential security '
                            'breach.</p>',
        'clip': 'Copy to clipboard',
        'create link': 'Create link',
        'download?': 'Download this secret?',
        'download!': 'Download the secret',
        'download done': '&#x2705; File retrieved',
        'error': 'Error',
        'only once': 'You can only do this once.',
        'reveal!': 'Reveal the secret',
        'reveal?': 'Reveal this secret?',
        'secret': 'Secret',
        'share new secret': 'Share a new secret',
        'share new file': 'Share a new file',
        'share this': 'Share this link',
        'share this desc': 'Send this link to someone else. <em>It will '
                           'be valid for 7 days.</em>',
        'title': 'Share a secret',
        'welcome desc': 'Enter your text into the box below. Once you '
                        'hit the button, you will get a link that you '
                        'can send to someone else. That link can only '
                        'be used once.',
        'welcome maybe file': 'Alternatively, you can '
                              '<a href="/file">upload a file</a>.',
        'welcome maybe text': 'Alternatively, you can '
                              '<a href="/">use plain text</a>.',
        'welcome file': 'Select the file to upload below. Once you hit '
                        'the button, you will get a link that you can '
                        'send to someone else. That link can only be '
                        'used once.',
        'welcome file max': 'Maximum allowed size',
        'wrong key': 'Wrong key. Secret has been destroyed.',
        'your secret': 'Here’s your secret. It is no longer accessible '
                       'through the link, so copy it <em>now</em>.',
    },
    'de': {
        'already revealed': '<p>Die vertraulichen Daten wurden bereits '
                            'abgerufen.</p><p>Falls Sie Empfänger*in '
                            'der Daten sind, diese aber nicht selbst '
                            'abgerufen haben, sollten Sie die '
                            'Versender*in über die potentielle '
                            'Kompromittierung informieren.</p>',
        'clip': 'In die Zwischenablage kopieren',
        'create link': 'Link erzeugen',
        'download?': 'Vertrauliche Daten herunterladen?',
        'download!': 'Vertrauliche Daten herunterladen',
        'download done': '&#x2705; Bereits heruntergeladen',
        'error': 'Fehler',
        'only once': 'Sie können diesen Vorgang nur <em>einmalig</em> '
                     'durchführen.',
        'reveal!': 'Vertrauliche Daten anzeigen',
        'reveal?': 'Vertrauliche Daten anzeigen?',
        'secret': 'Vertrauliche Daten',
        'share new secret': 'Neue vertrauliche Daten',
        'share new file': 'Neue vertrauliche Datei hochladen',
        'share this': 'Geben Sie diesen Link weiter',
        'share this desc': 'Geben Sie den folgenden Link weiter. <em>Er '
                           'ist nur für 7 Tage gültig.</em>',
        'title': 'Vertrauliche Daten weitergeben',
        'welcome desc': 'Geben Sie Ihre vertraulichen Daten in die '
                        'Textbox unten ein. Sobald Sie den Knopf '
                        'betätigen, erhalten Sie einen Link, den Sie '
                        'weitergeben können. Dieser Link kann nur ein '
                        'einziges Mal abgerufen werden.',
        'welcome maybe file': 'Alternativ können Sie '
                              '<a href="/file">eine Datei hochladen</a>.',
        'welcome maybe text': 'Alternativ können Sie '
                              '<a href="/">einfachen Text verwenden</a>.',
        'welcome file': 'Wählen Sie die hochzuladende Datei aus. Sobald '
                        'Sie den Knopf betätigen, erhalten Sie einen '
                        'Link, den Sie weitergeben können. Dieser Link '
                        'kann nur ein einziges Mal abgerufen werden.',
        'welcome file max': 'Maximal erlaubte Größe',
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
    css_url = environ.get('FLUESTERFIX_CSS', url_for('static', filename='style.css'))
    logo_url = environ.get('FLUESTERFIX_LOGO', url_for('static', filename='logo.png'))
    logo_dark_url = environ.get('FLUESTERFIX_LOGO_DARK', url_for('static', filename='logo-darkmode.png'))
    logo_alt = environ.get('FLUESTERFIX_LABEL', 'seibert//')

    return f'''<!DOCTYPE html>
<html lang="{get_lang()}">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width,initial-scale=1.0">
        <title>{_('title')}</title>
        <link rel="stylesheet" href="{ css_url }" type="text/css">
        <script src="{ url_for('static', filename='clipboard.js') }"></script>
    </head>
    <body>
        <a href="/" class="headerlink">
            <picture>
                <source srcset="{ logo_dark_url }" media="(prefers-color-scheme: dark)">
                <img src="{ logo_url }" id="logo" alt="{ logo_alt }">
            </picture>
        </a>
        {body}
    </body>
</html>'''


def max_size_msg():
    max_size_env = environ.get('FLUESTERFIX_MAX_FILE_SIZE')
    if max_size_env is None:
        return ''

    max_size = int(max_size_env)
    if max_size is not None:
        for div, suff in (
            (1_000_000_000, 'GB'),
            (1_000_000, 'MB'),
            (1_000, 'kB'),
        ):
            if max_size >= div:
                max_size_human = f'{max_size // div} {suff}'
                break
        else:
            max_size_human = f'{max_size} Bytes'

        return f'{_("welcome file max")}: {max_size_human}.'
    else:
        return ''


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
        return None, None, ALREADY_REVEALED

    # Now that we have "locked" this sid, we can safely read it and then
    # destroy it.
    with open(join(DATA, locked_sid, 'secret'), 'rb') as fp:
        secret_bytes = fp.read()
    run(['/usr/bin/shred', join(DATA, locked_sid, 'secret')])

    try:
        with open(join(DATA, locked_sid, 'filename'), 'r') as fp:
            filename = fp.read()
        run(['/usr/bin/shred', join(DATA, locked_sid, 'filename')])
    except FileNotFoundError:
        filename = None

    rmtree(join(DATA, locked_sid))

    # Restore padding. (No point in using something like a while loop
    # here, we checked for an explicit length earlier.)
    key += '='
    key = key.replace('_', '/')
    key_bytes = b64decode(key.encode('ASCII'))
    try:
        box = SecretBox(key_bytes)
        decrypted_bytes = box.decrypt(secret_bytes)
    except Exception:
        return None, None, WRONG_KEY
    return decrypted_bytes, filename, OK


def secret_exists(sid):
    return isdir(join(DATA, sid)), isfile(join(DATA, sid, 'filename'))


def store(secret_bytes, filename):
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
        fp.write(box.encrypt(secret_bytes))

    if filename is not None:
        with open(join(DATA, sid, 'filename'), 'w') as fp:
            fp.write(filename)

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
def form_plain():
    return html(f'''
        <h1>{_('share new secret')}</h1>
        <p>{_('welcome desc')}</p>
        <p>{_('welcome maybe file')}</p>
        <form action="/new" method="post">
            <textarea name="data"></textarea>
            <input type="submit" value="&#x1f517; {_('create link')}">
        </form>
    ''')


@app.route('/file')
def form_file():
    max_size = f'<p>{max_size_msg()}</p>'
    return html(f'''
        <h1>{_('share new file')}</h1>
        <p>{_('welcome file')}</p>
        <p>{_('welcome maybe text')}</p>
        {max_size}
        <form action="/new" method="post" enctype="multipart/form-data">
            <input type="file" name="file">
            <input type="submit" value="&#x1f517; {_('create link')}">
        </form>
    ''')


@app.route('/new', methods=['POST'])
def new():
    try:
        if request.is_json:
            if 'data_base64' in request.json and 'filename' in request.json:
                secret_bytes = b64decode(request.json['data_base64'])
                filename = request.json['filename']
            else:
                secret_bytes = request.json['data'].encode('UTF-8')
                filename = None
        elif request.form.get('data'):
            secret_bytes = request.form['data'].encode('UTF-8')
            filename = None
        else:
            secret_bytes = request.files['file'].read()
            filename = request.files['file'].filename
    except Exception:
        return 'Garbage', 400

    if filename is None and len(secret_bytes.strip()) <= 0:
        if request.is_json:
            return jsonify({
                'status': 'error',
                'msg': 'empty secret',
            }), 400
        else:
            return redirect(url_for('form_plain'))

    sid, key = store(secret_bytes, filename)
    scheme = request.headers.get('x-forwarded-proto', 'http')
    host = request.headers.get('x-forwarded-host', request.headers['host'])
    sid_url = f'{scheme}://{host}/get/{sid}/{key}'

    if request.is_json:
        return jsonify({
            'status': 'ok',
            'secret_link': sid_url
        }), 201
    else:
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
    exists, as_file = secret_exists(sid)
    if exists:
        if as_file:
            h1 = _('download?')
            btn = _('download!')
            btn_js = (
                'id="button" '
                'onclick="'
                    'document.getElementById(\'button\').disabled = true;'
                    'document.getElementById(\'button\').value = \'' +
                        _('download done') +
                    '\';'
                    'document.getElementById(\'form\').submit();'
                '"'
            )
            icon = '&#x1f4be;'
        else:
            h1 = _('reveal?')
            btn = _('reveal!')
            btn_js = ''
            icon = '&#x1f50d;'

        # FIXME Without that hidden field, lynx insists on doing GET. Is
        # that a bug in lynx or is it invalid to POST empty forms?
        return html(f'''
            <h1>{h1}</h1>
            <p>{_('only once')}</p>
            <form id="form" action="/reveal/{sid}/{key}" method="post">
                <input name="compat" type="hidden" value="lynx needs this">
                <input type="submit" value="{icon} {btn}" {btn_js}>
            </form>
        ''')
    else:
        return html(f'''
            <h1>{_('error')}</h1>
            {_('already revealed')}
        ''')


@app.route('/reveal/<sid>/<key>', methods=['POST'])
def reveal(sid, key):
    validate_key(key)
    validate_sid(sid)
    secret_bytes, filename, status = retrieve(sid, key)
    if status == ALREADY_REVEALED:
        return html(f'''
            <h1>{_('error')}</h1>
            {_('already revealed')}
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
    elif filename is not None:
        # We usually return "HTTP 410" to indicate to browsers that they
        # don't need to cache this response. This doesn't work for
        # "downloads", it confuses some browsers and they don't download
        # anything -- and it doesn't make a lot of sense anyway to use
        # 410 here.

        # HTTP Headers can only be ascii, to encode UTF-8 filenames a special header tag an encoding is needed:
        # https://stackoverflow.com/a/20933751
        # Code for Flask specifically was taken from
        # https://stackoverflow.com/a/43376150
        try:
            filename.encode("ascii")
        except UnicodeEncodeError:
            simple = unicodedata.normalize("NFKD", filename)
            simple = simple.encode("ascii", "ignore").decode("ascii")
            # safe = RFC 5987 attr-char
            quoted = quote(filename, safe="!#$&+-.^_`|~")
            names = {"filename": simple, "filename*": f"UTF-8''{quoted}"}
        else:
            names = {"filename": filename}

        response = make_response(secret_bytes, 200)
        response.headers.set('Content-Disposition', 'attachment', **names)
        response.headers.set('Content-Type', 'application/octet-stream')
        return response
    else:
        # Show all lines, if possible. Never show more than 100, though.
        # CSS also sets a min-height for this.
        secret = secret_bytes.decode('UTF-8')
        lines = min(len(secret.split('\n')), 100)
        return html(f'''
            <h1>{_('secret')}</h1>
            <p>{_('your secret')}</p>
            <textarea rows="{lines}" id="copytarget">{escape(secret)}</textarea>
            <p><span class="button" onclick="copy()">&#x1f4cb; {_('clip')}</span></p>
        '''), 410


if __name__ == '__main__':
    app.run(host='::')
