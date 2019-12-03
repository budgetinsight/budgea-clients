<?php
/*
 * Copyright(C) 2014-2020      Budget Insight
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
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

namespace Budgea;

/**
 * Class Client
 * v 2.1.0 - 2019-12-01
 * @package Budgea
 */

class Client {

	protected $settings;
	protected $access_token;
	protected $access_token_type = 'Bearer';
	protected $access_token_param_name = 'token';

	public function __construct($domain, $settings = []) {
		$this->settings = [
			'base_url' => 'https://' . $domain . '/2.0',
			'endpoints' => [
				'authorization' => '/auth/share/',
				'token' => '/auth/token/access',
				'code' => '/auth/token/code'
			],
			'client_id' => NULL,
			'client_secret' => NULL,
			'http_headers' => [],
		];
		$this->settings = array_merge($this->settings, $settings);

		if (isset($settings['webview']) && $settings['webview'] == 'v2'):
			$this->settings['endpoints']['connect'] = '/auth/webview/connect/';
			$this->settings['endpoints']['manage'] = '/auth/webview/manage';
			$this->settings['endpoints']['transfer'] = '/auth/webview/transfer';
		endif;
	}

	/**
     * @param $client_id
     */
	public function setClientId($client_id) {
		$this->settings['client_id'] = $client_id;
	}

	/**
     * @param $client_secret
     */
	public function setClientSecret($client_secret) {
		$this->settings['client_secret'] = $client_secret;
	}

	/**
     * @param $token
     */
	public function setAccessToken($token) {
		$this->access_token = $token;
	}

	/**
     * @return mixed
     */
	public function getAccessToken() {
		return $this->access_token;
	}

    /**
     * @param $resource_url
     * @param array $params
     * @return array
     * @throws AuthRequired
     * @throws InvalidAccessTokenType
     */
    public function get($resource_url, $params = []) {
    	return $this->fetch($resource_url, $params);
    }
    
    /**
     * @param $url
     * @return string
     */
    public function absurl($url) {
    	$url = $url[0] == '/' ? $this->settings['base_url'] . $url : $url;

    	return $url;
    }

	/**
	 * @param null $state
	 * @return bool
	 * @throws AuthFailed
	 * @throws ConnectionError
	 * @throws StateInvalid
	 */
	public function handleCallback($state = NULL) {
		if (isset($_GET['error']))
			throw new AuthFailed($_GET['error']);
		if (!isset($_GET['code']))
			return FALSE;
		if ($state !== NULL && (!isset($_GET['state']) || $_GET['state'] != $state))
            throw new StateInvalid();
		
		$params = ['code' => $_GET['code'], 'client_id' => $this->settings['client_id'], 'client_secret' => $this->settings['client_secret']];
		if (isset($this->settings['redirect_uri']))
			$params['redirect_uri'] = $this->settings['redirect_uri'];

		$http_headers = [];
		$response = $this->executeRequest($this->settings['endpoints']['token'], $params, 'POST', $http_headers);

		if (isset($response['result']['error']))
			throw new AuthFailed($response['result']['error']);
		$this->access_token = $response['result']['access_token'];
		$this->acess_token_type = strtolower($response['result']['token_type']);

		return $state || TRUE;
	}
	
	/**
     * @param string $text
     * @param string $state
     * @return string
     */
	public function getConnectButton($text, $state = '') {
				$button = '
					<a href="' . $this->getConnectUrl($state) . '"
						style="display: inline-block; background: #ff6100; padding: 8px 16px; border-radius: 4px; color: white; text-decoration: none; font: 12pt/14pt \'Roboto\', sans-serif">
						' . htmlentities($text) . '
					</a>';
        return $button;
		}
		
		/**
		 * Compatibility alias for getConnectButton()
		 */
		public function getAuthenticationButton($text = 'Partager ses comptes', $state = '') {
			return $this->getConnectButton($text, $state);
		}

    /**
     * @param string $text
     * @param string $state
     * @return string
     */
    public function getManageButton($text, $state = '') {
				$button = '
					<a href="' . htmlentities($this->getManageUrl($state)) . '"
						style="display: inline-block; background: #ff6100; padding: 8px 16px; border-radius: 4px; color: white; text-decoration: none; font: 12pt/14pt \'Roboto\', sans-serif">
						' . htmlentities($text) . '
					</a>';
        return $button;
    }

		/**
		 * Compatibility alias for getManageButton()
		 */
    public function getSettingsButton($text = 'Modifier ses comptes', $state = '') {
			return $this->getManageButton($text, $state);
		}

    /**
     * @param string $state
		 * @param string $connectorCapabilities
     * @return string
     */
    public function getConnectUrl($state = '', $connectorCapabilities = 'bank') {
    	$params = [
    		'response_type' => 'code',
    		'client_id' => $this->settings['client_id'],
    		'state' => $state,
        'connector_capabilities' => $connectorCapabilities,
    	];

    	!isset($this->settings['redirect_uri']) ?: $params['redirect_uri'] = $this->settings['redirect_uri'];

    	return $this->absurl($this->settings['endpoints']['connect'] . '?' . http_build_query($params, NULL, '&'));
		}
		
		/**
		 * Compatibility alias for getConnectUrl()
		 */
    public function getAuthenticationUrl($state = '', $connectorCapabilities = 'bank') {
			return $this->getConnectUrl($state, $connectorCapabilities);
		}

    /**
     * @param string $state
     * @return string
     * @throws AuthRequired
     * @throws InvalidAccessTokenType
     */
    public function getManageUrl($state = '') {
    	$response = $this->fetch($this->settings['endpoints']['code']);
    	$params = [
    		'response_type' => 'code',
    		'client_id' => $this->settings['client_id'],
    		'state' => $state
    	];

    	!isset($this->settings['redirect_uri']) ?: $params['redirect_uri'] = $this->settings['redirect_uri'];

    	if (isset($this->settings['endpoints']['manage']) && $this->settings['endpoints']['manage'] != NULL):
    		return $this->absurl($this->settings['endpoints']['manage'] . '?' . http_build_query($params, NULL, '&') . '#' . $response['code']);
    	else:
    		return $this->absurl($this->settings['endpoints']['connect'] . '?' . http_build_query($params, NULL, '&') . '#' . $response['code']);
    	endif;
		}
		
		/**
		 * Compatibility alias for getManageUrl()
		 */
    public function getSettingsUrl($state = '') {
			return $this->getManageUrl($state);
		}

    /**
		 * @param string $state
		 * @return string
		 * @throws AuthRequired
		 * @throws InvalidAccessTokenType
		 */
    public function getTransferUrl($state = '') {
    	$response = $this->fetch($this->settings['endpoints']['code']);
    	$params = [
    		'state' => $state
    	];

    	!isset($this->settings['transfer_redirect_uri']) ?: $params['redirect_uri'] = $this->settings['transfer_redirect_uri'];

    	return $this->absurl($this->settings['endpoints']['transfer'] . '?' . http_build_query($params, NULL, '&') . '#' . $response['code']);
		}
		
		/**
		 * Compatibility alias for getTransferUrl()
		 */
    public function getTransfersUrl($state = '') {
			return $this->getTransferUrl($state);
		}

    /**
     * @param string $expand
     * @return mixed
     */
    public function getAccounts($expand = '') {
    	$expandArray = !empty($expand) ? ['expand' => $expand] : [];
    	$res = $this->get('/users/me/accounts', $expandArray);

    	return $res['accounts'];
    }

    /**
     * @param string $account_id
     * @return mixed
     */
    public function getTransactions($account_id = '') {
    	if ($account_id)
            $res = $this->get('/users/me/accounts/' . $account_id . '/transactions', ['expand' => 'category']);
        else
            $res = $this->get('/users/me/transactions', ['expand' => 'category']);

        return $res['transactions'];
    }

    /**
     * @param $protected_resource_url
     * @param array $params
     * @param string $http_method
     * @param array $http_headers
     * @return array
     * @throws AuthRequired
     * @throws ConnectionError
     * @throws InvalidAccessTokenType
     */
    public function fetch($protected_resource_url, $params = [], $http_method = 'GET', $http_headers = []) {
    	$http_headers = array_merge($this->settings['http_headers'], $http_headers);
    	$protected_resource_url = $this->absurl($protected_resource_url);

    	if ($this->access_token):
    		switch ($this->access_token_type):
    			case 'url':
    				if (is_array($params))
    					$params[$this->access_token_param_name] = $this->access_token;
    				else
    					throw new RequireParamsAsArray('You need to give parameters as array if you want to give the token within the URI.');
    				break;
    			case 'Bearer':
    				$http_headers['Authorization'] = 'Bearer ' . $this->access_token;
    				break;
    			case 'oauth':
    				$http_headers['Authorization'] = 'OAuth ' . $this->access_token;
    			default:
    				throw new InvalidAccessTokenType();
    				break;
    		endswitch;
    	endif;

    	$r = $this->executeRequest($protected_resource_url, $params, $http_method, $http_headers);
    	switch ($r['code']):
    		case 200:
    			return $r['result'];
    			break;
    		case 401:
    		case 403:
    			throw new AuthRequired();
    			break;
    	endswitch;

    	return $r;
    }

     /**
     * @param $url
     * @param array $params
     * @param string $http_method
     * @param array $http_headers
     * @return array
     * @throws ConnectionError
     */

    private function executeRequest($url, $params = [], $http_method = 'GET', array $http_headers = []) {
     	$curl_options = [
     		CURLOPT_RETURNTRANSFER => true,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_CUSTOMREQUEST => $http_method
     	];
     	$url = $this->absurl($url);

     	switch ($http_method):
     		case 'POST':
     			$curl_options[CURLOPT_POST] = TRUE;
     		case 'PUT':
     		case 'PATCH':
     			/**
                 * Passing an array to CURLOPT_POSTFIELDS will encode the data as multipart/form-data,
                 * while passing a URL-encoded string will encode the data as application/x-www-form-urlencoded.
                 * http://php.net/manual/en/function.curl-setopt.php
                 */
     			if (is_array($params))
     				$params = http_build_query($params, NULL, '&');
     			$curl_options[CURLOPT_POSTFIELDS] = $params;
     			break;
     		case 'HEAD':
     			$curl_options[CURLOPT_NOBODY] = TRUE;
     		case 'DELETE':
     		case 'GET':
     			!$params ?: $url .= '?' . (is_array($params) ? http_build_query($params, NULL, '&') : $params);
     		default:
     			break;
     	endswitch;

     	$curl_options[CURLOPT_URL] = $url;

     	if (is_array($http_headers)) {
     		$header = [];
     		foreach ($http_headers as $key => $value)
     			$header[] = "$key: $value";
     		$curl_options[CURLOPT_HTTPHEADER] = $header;
     	}

     	$ch = curl_init();
     	curl_setopt_array($ch, $curl_options);
     	curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, TRUE);
     	curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);

     	$result = curl_exec($ch);
     	$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
     	$content_type = curl_getinfo($ch, CURLINFO_CONTENT_TYPE);

     	if ($curl_error = curl_error($ch))
     		throw new ConnectionError($curl_error);
     	else
     		$decode = json_decode($result, TRUE);
     	curl_close($ch);

     	return [
     		'result' => (NULL == $decode) ? $result : $decode,
     		'code' => $http_code,
     		'content_type' => $content_type,
     	];
    }
}

class Exception extends \Exception {
}
class ConnectionError extends Exception {
}
class InvalidAccessTokenType extends Exception {
}
class NoPermission extends Exception {
}
class AuthRequired extends Exception {
}
class AuthFailed extends Exception {
}
class StateInvalid extends Exception {
}
class RequireParamsAsArray extends \InvalidArgumentException {
}
?>