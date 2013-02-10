import os
import requests
from requests_oauthlib import OAuth1
from flask import Flask, request, session
from flask import render_template, url_for, redirect, abort, flash
from session import RedisSessionInterface
from oauth import get_request_token, get_access_token

app = Flask(__name__)

# Basic configuration
app.config.update(
    DEBUG = True,
    SECRET_KEY = '\x7f\xd5\xf3\n1\x03/\xc5\x15\xf0q\xf1\x18\xda\x08h`Z\xad\xa8\xaa\rm\xcb',
    SESSION_INTERFACE = RedisSessionInterface(prefix='o2:session:'),
    SESSION_COOKIE_HTTPONLY = True,
    SESSION_COOKIE_SECURE = True,
)

# OAuth 1a config
OAUTH_KEY = 'xhkYS0RoJ7hY70m1nTBl'
OAUTH_SECRET = os.environ.get('OAUTH_SECRET')
BASE_OAUTH_URL = 'https://planningcenteronline.com/oauth/'
REQUEST_TOKEN_URL = BASE_OAUTH_URL + 'request_token'
AUTHORIZE_URL = BASE_OAUTH_URL + 'authorize'
ACCESS_TOKEN_URL = BASE_OAUTH_URL + 'access_token'
CALLBACK_URL = 'http://o2.dbrgn.ch/login/callback'


@app.context_processor
def inject_login_status():
    return {
        'is_logged_in': 'access_token' in session,
    }


@app.route('/')
def home():
    return render_template('home.html', session=session)


@app.route('/login')
def login():
    """OAuth login: Obtain a request token and redirect user to authorization
    page."""

    # Obtain a request token
    args = [OAUTH_KEY, OAUTH_SECRET, REQUEST_TOKEN_URL, CALLBACK_URL]
    resource_owner_key, resource_owner_secret = get_request_token(*args)

    # Store key and secret in session
    session['request_token'] = resource_owner_key
    session['request_token_secret'] = resource_owner_secret

    # Redirect to authorization url
    redirect_url = '{0}?oauth_token={1}'.format(AUTHORIZE_URL, resource_owner_key)
    return redirect(redirect_url)


@app.route('/login/callback')
def oauth_callback():
    """Callback for OAuth1a authorization."""

    # Get verifier from GET arguments
    oauth_verifier = request.args.get('oauth_verifier', None)
    if oauth_verifier is None:
        abort(400, 'oauth_verifier arguments are missing.')

    # Request access token and token secret
    args = [OAUTH_KEY, OAUTH_SECRET, ACCESS_TOKEN_URL, oauth_verifier]
    resource_owner_key, resource_owner_secret = get_access_token(*args)

    # Store key and secret in session
    del session['request_token'], session['request_token_secret']
    session['access_token'] = resource_owner_key
    session['access_token_secret'] = resource_owner_secret

    # Redirect to home page
    flash('Login successful.')
    return redirect(url_for('home'))


@app.route('/logout')
def logout():
    """Clear session."""
    session.clear()
    flash('You were logged out.')
    return redirect(url_for('home'))


if __name__ == '__main__':
    if OAUTH_SECRET is None:
        raise EnvironmentError('Please set OAUTH_SECRET env variable.')
    app.run(port=8002)
