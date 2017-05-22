# encoding: UTF-8

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

begin
  require 'rubygems'
  require 'rest_client'
rescue LoadError
  puts %{
  I'm so sorry to ask you for the rest_client gem. \
  In fact ruby has no efficent HTTP client at this time (w/o big bug or missing feature)

  $ gem install rest_client -v 1.7.3
        }
  exit 1
end
require 'base64'
require 'open-uri'
require 'json'

# Usage
#
#   Normal flow with `client_id` and `client_secret`
#   ```
#   require 'budgea'
#   management_token = "XXXXXX"
#   budgea_client = Budgea::Client.new 'XXX.biapi.pro', { client_id: ENV['BUDGEA_CLIENT_ID'],
#                                                  client_secret: ENV['BUDGEA_CLIENT_SECRET'],
#                                                  redirect_uri: 'https://lvh.me:3000/user/settings' }
#
#   puts client.get_authentication_url('', types: 'providers')    # Example with a 'provider' Webview
#   puts client.get_authentication_button('', types: 'providers') # Example with a 'provider' Webview
#   ```
#
#   With a management token
#   ```
#   require 'budgea'
#   management_token = "XXXXXX" # TODO LIEN VERS PAGE MANAGEMENT TOKEN
#   budgea_client = Budgea::Client.new 'XXXXXX.biapi.pro', { access_token: management_token, access_token_type: 'bearer' }
#
#   budgea_client.get('/clients') # Adminitration endpoints in API Reference
#   ```

module Budgea
  class Client
    VERSION = '2.0.0'.freeze

    attr_accessor :client_id
    attr_accessor :client_secret
    attr_accessor :access_token
    attr_writer   :access_token_type

    def access_token_type
      @access_token_type || 'bearer'
    end

    def initialize(domain, settings = {})
      @settings = {
        authorization_endpoint: '/auth/share/',
        token_endpoint: '/auth/token/access',
        code_endpoint: '/auth/token/code',
        base_url: "https://#{domain}/2.0",
        http_headers: { 'User-Agent': "BudgeaAPI Client #{VERSION}" },
        client_id: nil,
        client_secret: nil,
        access_token_param_name: 'token',
        redirect_uri: nil,
        transfers_endpoint: '/webview/transfers/accounts',
        transfers_redirect_uri: nil
      }.merge(settings)

      @access_token      = @settings[:access_token] ? @settings[:access_token] : nil
      @access_token_type = @settings[:access_token_type] ? @settings[:access_token_type] : 'bearer'
    end

    def handle_callback(params = {})
      raise AuthFailed, params['error'] || 'Authentication failed' if params['error']
      return false unless params.key?('code')
      new_params = { code: params['code'], redirect_uri: @settings[:redirect_uri], grant_type: 'authorization_code' }

      uri = URI.parse(@settings[:base_url] + @settings[:token_endpoint])
      #::RestClient.proxy = 'http://localhost:8888'
      resource = ::RestClient::Resource.new uri.to_s, @settings[:client_id], @settings[:client_secret]
      response = resource.post(new_params)

      raise ConnectionError, 'Can’t reach remote URI' unless response.code == 200

      json_response = JSON.parse response.to_str
      raise AuthFailed, json_response['error'] || 'Authentication failed' if json_response['error']

      @access_token = json_response['access_token']
      @access_token_type = json_response['token_type']
      params[:state] || true
    end

    # Method: get_authentication_url
    #
    # Parameter `types` can be either `providers` or `banks`
    #   Default value is `banks`, no need to specify it in this case
    #
    # Usage:
    #   client.get_authentication_url('')                     # Add a bank
    #    OR
    #   client.get_authentication_url('', types: 'providers') # Add a provider
    #
    def get_authentication_url(state = '', types: nil)
      query_string_params = {
        response_type: 'code',
        client_id: @settings[:client_id],
        redirect_uri: @settings[:redirect_uri],
        state: state
      }
      query_string_params[:types] = types.to_s if types.present?

      endpoint_uri_with_params(@settings[:authorization_endpoint], query_string_params)
    end

    # Usage
    #   client.get_authentication_button('Partager ses fournisseurs')                     # Add a bank
    #    OR
    #   client.get_authentication_button('Partager ses fournisseurs', types: 'providers') # Add a provider
    #
    def get_authentication_button(text, types: nil)
      authentication_url = get_authentication_url('', types: types)
      button_img_url = absurl('/auth/share/button_icon.png')

      button = "
                <a href='#{authentication_url}'
                   style='background: #ff6100;
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
                          border-radius: 4px'>
                       <img style='margin: 0 10px 0 0;
                                   vertical-align: middle;
                                   padding: 0'
                            src='#{button_img_url}' /> #{text}
                 </a>"
      button.html_safe
    end

    def get_settings_url(state = '', types: nil)
      code_endpoint_response = get(@settings[:code_endpoint])
      code_endpoint_response = JSON.parse(code_endpoint_response) if code_endpoint_response.is_a?(String)

      query_string_params = {
        response_type: 'code',
        client_id: @settings[:client_id],
        redirect_uri: @settings[:redirect_uri],
        state: state,
        code: code_endpoint_response['code']
      }
      query_string_params[:types] = types.to_s if types.present?

      endpoint_uri_with_params(@settings[:authorization_endpoint], query_string_params)
    end

    def get_transfers_url(state = '')
      code_endpoint_response = get(@settings[:code_endpoint])
      code_endpoint_response = JSON.parse(code_endpoint_response) if code_endpoint_response.is_a?(String)

      query_string_params = {
        redirect_uri: @settings[:transfers_redirect_uri],
        state: state,
        code: code_endpoint_response['code']
      }

      endpoint_uri_with_params(@settings[:transfers_endpoint], query_string_params)
    end

    def get(uri, params = {})
      fetch(uri, params)
    end

    def fetch(uri, params = {}, method = :get, http_headers = {})
      http_headers.merge!(@settings[:http_headers])
      # http_headers.merge!({:content_type => :json, :accept => :json})
      http_headers[:accept] = :json

      if @access_token
        case @access_token_type
        when 'url'
          raise ArgumentException, 'You need to give parameters as Hash if you want to give the token within the URI.' unless params.is_a?(Hash)
          params[@access_token_param_name] = @access_token
        when 'bearer'
          http_headers['Authorization'] = "Bearer #{@access_token}"
        when 'oauth'
          http_headers['Authorization'] = "OAuth #{@access_token}"
        else
          raise InvalidAccessTokenType, "Invalid access token type: #{@access_token_type}"
        end
      end

      # RestClient.proxy = 'http://localhost:8888'
      uri = absurl(uri)
      ressource = RestClient::Resource.new uri.to_s
      response = nil
      begin
        final_params = params.merge(http_headers)
        response = ressource.send(method, params.merge(final_params))
      rescue RestClient::Exception => e
        message = JSON.parse(e.response.to_str)
        raise(AuthRequired, message) if response.code.in?([401, 403])
        return message
      end

      if response.headers[:content_type] == 'application/json'
        JSON.parse(response.to_str)
      else
        response.to_str
      end
    end

    def get_accounts(_expand = nil)
      ret = get('/users/me/accounts')

      ret['accounts'] ? ret['accounts'].map { |account| Account.new(self, account) } : ret
    end

    def get_transactions(account_id = nil)
      ret = if account_id
              get("/users/me/accounts/#{account_id}/transactions", 'expand' => 'category')
            else
              get('/users/me/transactions/', 'expand' => 'category')
            end
      ret['transactions'] ? ret['transactions'].map { |transaction| Transaction.new(self, transaction) } : ret
    end

    private

    def absurl(url)
      url.start_with?('http') ? File.join(@settings[:base_url], url) : url
    end

    def endpoint_uri_with_params(endpoint_path, query_string_params)
      endpoint_url = File.join(@settings[:base_url], endpoint_path)

      uri = URI.parse(endpoint_url)
      uri.query = URI.encode_www_form(query_string_params)
      uri.to_s
    end
  end

  class Transaction
    attr_reader :id, :date, :value, :nature
    attr_reader :original_wording, :simplified_wording, :stemmed_wording
    attr_reader :category, :client
    attr_reader :state, :date_scraped, :rdate, :coming, :active, :comment

    def initialize(client, resp)
      @client             = client
      @id                 = resp['id']
      @date               = resp['date']
      @value              = resp['value']
      @nature             = resp['nature']
      @original_wording   = resp['original_wording']
      @simplified_wording = resp['simplified_wording']
      @stemmed_wording    = resp['stemmed_wording']
      @category           = client.get('category', nil)
      @state              = resp['state']
      @date_scraped       = resp['date_scraped']
      @rdate              = resp['rdate']
      @coming             = resp['coming']
      @active             = resp['active']
      @comment            = resp['comment']
    end
  end

  class Account
    attr_reader :client
    attr_reader :id, :number, :name, :balance, :last_update

    def initialize(client, response)
      @client      = client
      @id          = response['id']
      @number      = response['number']
      @name        = response['name']
      @balance     = response['balance']
      @last_update = response['last_update']
    end

    def transactions
      ret = client.get_transactions(id)
      ret['transactions'] ? ret['transactions'].map { |transaction| Transaction.new(client, transaction) } : ret
    end
  end

  class BudgeaException < RuntimeError; end
  class ConnectionError < BudgeaException; end
  class InvalidAccessTokenType < BudgeaException; end
  class AuthRequired < BudgeaException; end
  class AuthFailed < BudgeaException; end
end
