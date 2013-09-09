# coding=utf8
from __future__ import absolute_import, print_function, division

import os
from datetime import date, datetime, timedelta
from collections import defaultdict

from flask import Flask, request, session, escape
from flask import render_template, url_for, redirect, abort, flash

import requests
import grequests
from gevent.wsgi import WSGIServer
from requests_oauthlib import OAuth1
from oauth import get_request_token, get_access_token

from session import RedisSessionInterface


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
OAUTH_KEY = os.environ.get('OAUTH_KEY')
OAUTH_SECRET = os.environ.get('OAUTH_SECRET')
BASE_URL = 'https://www.planningcenteronline.com/'
BASE_OAUTH_URL = BASE_URL + 'oauth/'
REQUEST_TOKEN_URL = BASE_OAUTH_URL + 'request_token'
AUTHORIZE_URL = BASE_OAUTH_URL + 'authorize'
ACCESS_TOKEN_URL = BASE_OAUTH_URL + 'access_token'
CALLBACK_URL = 'http://o2.dbrgn.ch/login/callback'


### HELPER FUNCTIONS ###


def logged_in():
    return 'access_token' in session


def get_auth():
    assert logged_in()
    return OAuth1(OAUTH_KEY,
                  client_secret=OAUTH_SECRET,
                  resource_owner_key=session['access_token'],
                  resource_owner_secret=session['access_token_secret'])


def get_plans(service_type):
    """Get list of plans for specified service type."""

    # Fetch list of plan IDs
    oauth = get_auth()
    r = requests.get('{0}service_types/{1}/plans.json'.format(BASE_URL, service_type), auth=oauth)
    plan_ids = [plan['id'] for plan in r.json()]

    # Fetch each plan
    urls = ['{0}plans/{1}.json'.format(BASE_URL, plan_id) for plan_id in plan_ids]
    rs = (grequests.get(url, auth=oauth) for url in urls)
    responses = grequests.map(rs)
    return [r.json() for r in responses]


### CONTEXT PROCESSORS ###


@app.context_processor
def inject_login_status():
    return {'is_logged_in': logged_in()}


### AUTH ###


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


### MAIN PAGES ###


@app.route('/', methods=['GET'])
def home():
    context = {}
    if logged_in():
        oauth = get_auth()
        r = requests.get(BASE_URL + 'me.json', auth=oauth)
        data = r.json()
        context['first_name'] = data['first_name']
        context['last_name'] = data['last_name']
        # TODO save name into session
    return render_template('home.html', **context)


@app.route('/step0/', methods=['GET'])
def step0():
    """Step 0: Start wizard, get date range."""
    oauth = get_auth()

    context = {
        'start_date': date.today(),
        'end_date': date.today() + timedelta(90),
    }
    return render_template('step0.html', **context)


@app.route('/step1/', methods=['GET'])
def step1():
    """Step 1: Get service type."""
    oauth = get_auth()

    # Get arguments via GET
    start_date = escape(request.args['start_date'])
    end_date = escape(request.args['end_date'])

    # Fetch service types
    r = requests.get(BASE_URL + 'organization.json', auth=oauth)
    data = r.json()
    service_types = [
        {'id': st['id'], 'name': st['name']}
        for st in data['service_types']
    ]

    context = {
        'start_date': start_date,
        'end_date': end_date,
        'service_types': service_types,
    }
    return render_template('step1.html', **context)


@app.route('/step2/', methods=['GET'])
def step2():
    """Step 2: Get categories."""

    # Get arguments via GET
    start_date = escape(request.args['start_date'])
    end_date = escape(request.args['end_date'])
    service_type = escape(request.args['service_type'])

    # Get all the categories and positions
    plans = get_plans(service_type)
    categories = defaultdict(set)
    for plan in plans:
        for job in plan['plan_people']:
            categories[job['category_name']].add(job['position'])

    context = {
        'start_date': start_date,
        'end_date': end_date,
        'service_type': service_type,
        'categories': categories,
    }
    return render_template('step2.html', **context)


@app.route('/matrix/', methods=['GET'])
def matrix():
    """Show the Matrix."""

    # Get arguments via GET
    start_date = escape(request.args['start_date'])
    end_date = escape(request.args['end_date'])
    service_type = escape(request.args['service_type'])
    category = escape(request.args['category'])
    jobs = map(escape, request.args.getlist('jobs'))

    # Prepare variables
    dates = set()
    people = defaultdict(lambda: defaultdict(set))
    sort_date_format = '%Y/%m/%d %H:%M:%S'

    # Loop over and process plans
    plans = get_plans(service_type)
    for plan in plans:
        sort_date = plan['sort_date'].rsplit(' ', 1)[0]
        date_obj = datetime.strptime(sort_date, sort_date_format)
        dates.add(date_obj)
        for job in plan['plan_people']:
            if not job['category_name'] == category:
                continue  # Skip irrelevant categories
            if not job['position'] in jobs:
                continue  # Skip irrelevant jobs
            if job['status'] not in ['C', 'U']:
                continue  # Skip declined jobs
            name = job['person_name']
            people[name][date_obj].add(job['position'])
            people[name]['count'] = people[name].get('count', 0) + 1

    context = {
        'dates': sorted(dates),
        'people': people,
    }
    return render_template('matrix.html', **context)


if __name__ == '__main__':
    if OAUTH_KEY is None:
        raise EnvironmentError('Please set OAUTH_KEY env variable.')
    if OAUTH_SECRET is None:
        raise EnvironmentError('Please set OAUTH_SECRET env variable.')
    http_server = WSGIServer(('', 8002), app)
    http_server.serve_forever()
