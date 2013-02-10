import urlparse
import requests
from requests_oauthlib import OAuth1
from flask import request, session


def get_request_token(oauth_key, oauth_secret, request_token_url, callback_url):
    oauth = OAuth1(oauth_key, client_secret=oauth_secret)
    data = {'oauth_callback': callback_url}
    r = requests.post(url=request_token_url, auth=oauth, data=data)
    credentials = urlparse.parse_qs(r.content)
    resource_owner_key = credentials.get('oauth_token')[0]
    resource_owner_secret = credentials.get('oauth_token_secret')[0]
    return resource_owner_key, resource_owner_secret


def get_access_token(oauth_key, oauth_secret, access_token_url, oauth_verifier):
    oauth = OAuth1(oauth_key,
            client_secret=oauth_secret,
            resource_owner_key=session['request_token'],
            resource_owner_secret=session['request_token_secret'],
            verifier=oauth_verifier)
    r = requests.post(url=access_token_url, auth=oauth)
    credentials = urlparse.parse_qs(r.content)
    resource_owner_key = credentials.get('oauth_token')[0]
    resource_owner_secret = credentials.get('oauth_token_secret')[0]
    return resource_owner_key, resource_owner_secret
