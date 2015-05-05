<?php

/*
 * Copyright(C) 2014-2015      Budget Insight
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this progrram. If not, see <http://www.gnu.org/licenses/>.
 */

namespace Budgea;

class Client
{
    protected $settings;
    protected $access_token;
    protected $access_token_type = "bearer"; // default token type is Bearer

    public function __construct($domain, $settings = array()) {
        $this->settings = array('authorization_endpoint'   => '/auth/share/',
                                'token_endpoint'           => '/auth/token/access',
                                'code_endpoint'            => '/auth/token/code',
                                'base_url'                 => 'https://'.$domain.'/2.0',
                                'http_headers'             => array(),
                                'client_id'                => NULL,
                                'client_secret'            => NULL,
                                'access_token_param_name'  => 'token',
                               );
        $this->settings = array_merge($this->settings, $settings);
    }

    public function setClientId($client_id) {
        $this->settings['client_id'] = $client_id;
    }

    public function setClientSecret($client_secret) {
        $this->settings['client_secret'] = $client_id;
    }

    public function setAccessToken($token) {
        $this->access_token = $token;
    }

    public function getAccessToken() {
        return $this->access_token;
    }

    public function handleCallback($state = NULL) {
        if (isset($_GET['error']))
            throw new AuthFailed($_GET['error']);

        if (!isset($_GET['code']))
            return FALSE;

        if ($state !== NULL && (!isset($_GET['state']) || $_GET['state'] != $state))
            throw new StateInvalid();

        $params = array('code' => $_GET['code'], 'redirect_uri' => $this->settings['redirect_uri']);

        $params['grant_type'] = 'authorization_code';
        $http_headers = array();
        $http_headers['Authorization'] = 'Basic ' . base64_encode($this->settings['client_id'] .  ':' . $this->settings['client_secret']);

        $response = $this->executeRequest($this->settings['token_endpoint'], $params, 'POST', $http_headers);

        if (isset($response['result']['error']))
            throw new AuthFailed($response['result']['error']);

        $this->access_token = $response['result']['access_token'];
        $this->access_token_type = strtolower($response['result']['token_type']);

        return $state || TRUE;
    }

    public function getAuthenticationButton($text = 'Partager ses comptes')
    {
        $button = '<a href="'.htmlentities($this->getAuthenticationUrl()).'"
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
                             src="'.htmlentities($this->absurl('/auth/share/button_icon.png')).'" />
                        '.htmlentities($text).'
                 </a>';
        return $button;
    }

    public function getAuthenticationUrl($state = '')
    {
        $parameters = array(
            'response_type' => 'code',
            'client_id'     => $this->settings['client_id'],
            'redirect_uri'  => $this->settings['redirect_uri'],
            'state'         => $state,
        );
        return $this->absurl($this->settings['authorization_endpoint'] . '?' . http_build_query($parameters, null, '&'));
    }

    public function getSettingsUrl($state = '')
    {
        $response = $this->fetch($this->settings['code_endpoint']);
        $parameters = array(
            'response_type' => 'code',
            'client_id'     => $this->settings['client_id'],
            'redirect_uri'  => $this->settings['redirect_uri'],
            'state'         => $state,
            'code'          => $response['code'],
        );
        return $this->absurl($this->settings['authorization_endpoint'] . '?' . http_build_query($parameters, null, '&'));

    }

    public function get($resource_url, $parameters = array()) {
        return $this->fetch($resource_url, $parameters);
    }

    public function getAccounts($expand = '') {
        $res = $this->get('/users/me/accounts');
        return $res['accounts'];
    }

    public function getTransactions($account_id = '') {
        if ($account_id)
            $res = $this->get('/users/me/accounts/'.$account_id.'/transactions', array('expand' => 'category'));
        else
            $res = $this->get('/users/me/transactions', array('expand' => 'category'));

        return $res['transactions'];
    }

    public function absurl($url) {
        if ($url[0] == '/')
            $url = $this->settings['base_url'].$url;

        return $url;
    }

    public function fetch($protected_resource_url, $parameters = array(), $http_method = 'GET', array $http_headers = array())
    {
        $http_headers = array_merge($this->settings['http_headers'], $http_headers);

        $protected_resource_url = $this->absurl($protected_resource_url);

        if ($this->access_token) {
            switch ($this->access_token_type) {
                case 'url':
                    if (is_array($parameters)) {
                        $parameters[$this->settings['access_token_param_name']] = $this->access_token;
                    } else {
                        throw new RequireParamsAsArray('You need to give parameters as array if you want to give the token within the URI.');
                    }
                    break;
                case 'bearer':
                    $http_headers['Authorization'] = 'Bearer ' . $this->access_token;
                    break;
                case 'oauth':
                    $http_headers['Authorization'] = 'OAuth ' . $this->access_token;
                    break;
                default:
                    throw new InvalidAccessTokenType();
                    break;
            }
        }

        $r = $this->executeRequest($protected_resource_url, $parameters, $http_method, $http_headers);
        switch($r['code']) {
            case 200:
                return $r['result'];
                break;
            case 401:
            case 403:
                throw new AuthRequired();
                break;
        }
        return $r;
    }

    private function executeRequest($url, $parameters = array(), $http_method = 'GET', array $http_headers = null)
    {
        $curl_options = array(
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_CUSTOMREQUEST  => $http_method
        );

        $url = $this->absurl($url);

        switch($http_method) {
            case 'POST':
                $curl_options[CURLOPT_POST] = true;
                /* No break */
            case 'PUT':
            case 'PATCH':

                /**
                 * Passing an array to CURLOPT_POSTFIELDS will encode the data as multipart/form-data,
                 * while passing a URL-encoded string will encode the data as application/x-www-form-urlencoded.
                 * http://php.net/manual/en/function.curl-setopt.php
                 */
                if(is_array($parameters)) {
                    $parameters = http_build_query($parameters, null, '&');
                }
                $curl_options[CURLOPT_POSTFIELDS] = $parameters;
                break;
            case 'HEAD':
                $curl_options[CURLOPT_NOBODY] = true;
                /* No break */
            case 'DELETE':
            case 'GET':
                if ($parameters)
                    $url .= '?' . (is_array($parameters) ? http_build_query($parameters, null, '&') : $parameters);
                break;
            default:
                break;
        }

        $curl_options[CURLOPT_URL] = $url;

        if (is_array($http_headers)) {
            $header = array();
            foreach($http_headers as $key => $parsed_urlvalue) {
                $header[] = "$key: $parsed_urlvalue";
            }
            $curl_options[CURLOPT_HTTPHEADER] = $header;
        }

        $ch = curl_init();
        curl_setopt_array($ch, $curl_options);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);

        $result = curl_exec($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $content_type = curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
        if ($curl_error = curl_error($ch)) {
            throw new ConnectionError($curl_error);
        } else {
            $json_decode = json_decode($result, true);
        }
        curl_close($ch);

        return array(
            'result' => (null === $json_decode) ? $result : $json_decode,
            'code' => $http_code,
            'content_type' => $content_type
        );
    }


}

class Exception extends \Exception {}
class ConnectionError extends Exception {}
class InvalidAccessTokenType extends Exception {}
class NoPermission extends Exception {}
class AuthRequired extends Exception {}
class AuthFailed extends Exception {}
class StateInvalid extends Exception {}

class RequireParamsAsArray extends \InvalidArgumentException {}

?>
