# -*- coding: utf-8 -*-

# MIT License
#
# Copyright (c) 2014-2020 Budget Insight
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.


import simplejson
import cgi
import urllib
import urllib2
from base64 import b64encode


class BudgeaException(Exception): pass
class ConnectionError(BudgeaException): pass
class InvalidAccessTokenType(BudgeaException): pass
class NoPermission(BudgeaException): pass
class AuthRequired(BudgeaException): pass
class AuthFailed(BudgeaException): pass
class StateInvalid(BudgeaException): pass

class RequireParamsAsArray(TypeError): pass


class Transaction(object):
    def __init__(self, client, resp):
        self.id = resp['id']
        self.date = resp['date']
        self.value = resp['value']
        self.nature = resp['nature']
        self.original_wording = resp['original_wording']
        self.simplified_wording = resp['simplified_wording']
        self.stemmed_wording = resp['stemmed_wording']
        self.category = resp.get('category', None)
        self.state = resp['state']
        self.date_scraped = resp['date_scraped']
        self.rdate = resp['rdate']
        self.coming = resp['coming']
        self.active = resp['active']
        self.comment = resp['comment']


class Account(object):
    def __init__(self, client, response):
        self.client = client
        self.id = response['id']
        self.number = response['number']
        self.name = response['name']
        self.balance = response['balance']
        self.last_update = response['last_update']

    @property
    def transactions(self):
        resp = self.client.get('/users/me/accounts/%s/transactions?expand=category' % self.id)
        return [Transaction(self.client, tr) for tr in resp['transactions']]


class Client(object):
    VERSION = '2.1.0'

    def __init__(self, domain, **kwargs):
        self.access_token = None
        self.access_token_type = 'bearer'

        self.settings = {'connect_endpoint':        '/auth/webview/connect',
                         'manage_endpoint':         '/auth/webview/manage',
                         'token_endpoint':          '/auth/token/access',
                         'code_endpoint':           '/auth/token/code',
                         'base_url':                'https://%s/2.0' % domain,
                         'http_headers':            {'User-Agent': 'BudgeaAPI Client/%s' % self.VERSION},
                         'client_id':               None,
                         'client_secret':           None,
                         'access_token_param_name': 'token',
                         'redirect_uri':            None,
                         'transfer_endpoint':       '/auth/webview/transfer',
                         'transfer_redirect_uri':   None,
                         'connector_capabilities':  None,
                        }
        self.settings.update(kwargs)

    def set_client_id(self, client_id):
        self.settings['client_id'] = client_id

    def set_client_secret(self, client_secret):
        self.settings['client_secret'] = client_secret

    def handle_callback(self, params, state=None):
        if 'error' in params:
            raise AuthFailed(params['error'])

        if not 'code' in params:
            return False

        if state is not None and (not 'state' in params or params['state'] != state):
            raise StateInvalid()

        p = {}
        p['code'] = params['code']
        p['redirect_uri'] = self.settings['redirect_uri']
        p['grant_type'] = 'authorization_code'

        headers = {}
        headers['Authorization'] = 'Basic %s' % b64encode('%s:%s:' % (self.settings['client_id'], self.settings['client_secret']))

        response = self.fetch(self.settings['token_endpoint'], p, 'POST', headers)

        if 'error' in response:
            raise AuthFailed(response['error'])

        self.access_token = response['access_token']
        self.access_token_type = response['token_type']

        return state or True



    def get_connect_button(self, text):
        button = """
                <a href="%s"
                    style="display: inline-block; background: #ff6100; padding: 8px 16px; border-radius: 4px; color: white; text-decoration: none; font: 12pt/14pt 'Roboto', sans-serif">
                    %s
                </a>""" % (cgi.escape(self.get_connect_url()),
                            cgi.escape(text))
        return button

    # Compatibility alias for get_connect_button
    def get_authentication_button(self, text):
        return self.get_connect_button(text)

    def get_connect_url(self, state=''):
        params = {'client_id':              self.settings['client_id'],
                  'redirect_uri':           self.settings['redirect_uri'],
                  'state':                  state,
                  'connector_capabilities': self.settings['connector_capabilities'],
                 }
        return self.absurl('%s?%s' % (self.settings['connect_endpoint'], urllib.urlencode(params)))

    # Compatibility alias for get_connect_url
    def get_authentication_url(self, state=''):
        return self.get_connect_url(state)

    def get_manage_url(self, state=''):
        response = self.fetch(self.settings['code_endpoint'])

        params = {'client_id':              self.settings['client_id'],
                  'redirect_uri':           self.settings['redirect_uri'],
                  'state':                  state,
                  'code':                   response['code'],
                  'connector_capabilities': self.settings['connector_capabilities'],
                 }
        return self.absurl('%s?%s' % (self.settings['manage_endpoint'], urllib.urlencode(params)))

    # Compatibility alias for get_manage_url
    def get_settings_url(self, state=''):
        return self.get_manage_url(state)

    def get_transfer_url(self, state=''):
        response = self.fetch(self.settings['code_endpoint'])

        params = {'client_id':      self.settings['client_id'],
                  'redirect_uri':   self.settings['transfer_redirect_uri'],
                  'state':          state,
                 }
        return self.absurl('%s?%s#%s' % (self.settings['transfer_endpoint'], urllib.urlencode(params), response['code']))

    # Compatibility alias for get_transfer_url
    def get_transfers_url(self, state=''):
        return self.get_transfer_url(state)

    def get(self, resource_url, params=None):
        return self.fetch(resource_url, params)

    @property
    def accounts(self):
        return [Account(self, acc) for acc in self.get('/users/me/accounts')['accounts']]

    @property
    def transactions(self):
        return [Transaction(self, tr) for tr in self.get('/users/me/transactions?expand=category')['transactions']]

    def absurl(self, url):
        if url.startswith('/'):
            url = self.settings['base_url'] + url
        return url

    def fetch(self, resource_url, params=None, http_method='GET', http_headers=None):
        headers = self.settings['http_headers'].copy()
        if http_headers:
            headers.update(http_headers)

        if params is None:
            params = {}

        resource_url = self.absurl(resource_url)

        if self.access_token:
            if self.access_token_type == 'url':
                params[self.settings['access_token_param_name']] = self.access_token
            elif self.access_token_type == 'bearer':
                headers['Authorization'] = 'Bearer %s' % self.access_token
            elif self.access_token_type == 'oauth':
                headers['Authorization'] = 'OAuth %s' % self.access_token
            else:
                raise InvalidAccessTokenType(self.access_token_type)

        try:
            r = self.execute_request(resource_url, params, http_method, headers)
        except urllib2.HTTPError as e:
            if e.code in (401,403):
                raise AuthRequired()
            raise e

        data = simplejson.load(r)
        return data

    def execute_request(self, url, params=None, http_method='GET', http_headers=None):
        url = self.absurl(url)

        data = None

        if http_method in ('POST', 'PUT', 'PATCH'):
            data = urllib.urlencode(params or {})
        elif params:
            url = '%s?%s' % (url, urllib.urlencode(params))

        opener = urllib2.build_opener()
        request = urllib2.Request(url, data, http_headers or {})
        request.get_method = lambda: http_method

        return opener.open(request)
