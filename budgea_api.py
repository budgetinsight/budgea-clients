# -*- coding: utf-8 -*-

# Copyright(C) 2014-2017      Budget Insight
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.


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
    VERSION = '2.0.0'

    def __init__(self, domain, **kwargs):
        self.access_token = None
        self.access_token_type = 'bearer'

        self.settings = {'authorization_endpoint':  '/auth/webview/',
                         'token_endpoint':          '/auth/token/access',
                         'code_endpoint':           '/auth/token/code',
                         'base_url':                'https://%s/2.0' % domain,
                         'http_headers':            {'User-Agent': 'BudgeaAPI Client/%s' % self.VERSION},
                         'client_id':               None,
                         'client_secret':           None,
                         'access_token_param_name': 'token',
                         'redirect_uri':            None,
                         'transfers_endpoint':      '/webview/transfers/accounts',
                         'transfers_redirect_uri':  None,
                         'types':                   None,
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
        p['grant_ type'] = 'authorization_code'

        headers = {}
        headers['Authorization'] = 'Basic %s' % b64encode('%s:%s:' % (self.settings['client_id'], self.settings['client_secret']))

        response = self.fetch(self.settings['token_endpoint'], p, 'POST', headers)

        if 'error' in response:
            raise AuthFailed(response['error'])

        self.access_token = response['access_token']
        self.access_token_type = response['token_type']

        return state or True



    def get_authentication_button(self, text):
        button = """
                  <a href="%s"
                     style="background: #ff6100;
                            color: #fff;
                            font-size: 14px;
                            font-weight: normal;
                            display: inline-block;
                            padding: 6px 12px;
                            white-space: nowrap;
                            line-height: 20px;
                            margin-bottom: 0;
                            text-align: center;
                            border: 1px solid #ff6100;
                            vertical-align: middle;
                            text-decoration: none;
                            border-radius: 4px">
                         <img style="margin: 0 10px 0 0;
                                     vertical-align: middle;
                                     padding: 0"
                              src="%s" /> %s
                   </a>""" % (cgi.escape(self.get_authentication_url()),
                              cgi.escape(self.absurl('/auth/share/button_icon.png')),
                              cgi.escape(text))
        return button

    def get_authentication_url(self, state=''):
        params = {'response_type':  'code',
                  'client_id':      self.settings['client_id'],
                  'redirect_uri':   self.settings['redirect_uri'],
                  'state':          state,
                  'types':          self.settings['types'],
                 }
        return self.absurl('%s?%s' % (self.settings['authorization_endpoint'], urllib.urlencode(params)))

    def get_settings_url(self, state=''):
        response = self.fetch(self.settings['code_endpoint'])

        params = {'response_type':  'code',
                  'client_id':      self.settings['client_id'],
                  'redirect_uri':   self.settings['redirect_uri'],
                  'state':          state,
                  'code':           response['code'],
                  'types':          self.settings['types'],
                 }
        return self.absurl('%s?%s' % (self.settings['authorization_endpoint'], urllib.urlencode(params)))

    def get_transfers_url(self, state=''):
        response = self.fetch(self.settings['code_endpoint'])

        params = {'redirect_uri':   self.settings['transfers_redirect_uri'],
                  'state':          state,
                 }
        return self.absurl('%s?%s#%s' % (self.settings['transfers_endpoint'], urllib.urlencode(params), response['code']))

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
