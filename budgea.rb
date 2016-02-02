# encoding: UTF-8

# Copyright(C) 2014-2015      Budget Insight
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
rescue LoadError => e
  puts %{
  I'm so sorry to ask you for the rest_client gem. In fact ruby has no efficent HTTP client at this time (w/o big bug or missing feature)

  $ gem install rest_client -v 1.7.3
        }
  exit 1
end
require 'base64'
require 'open-uri'
require 'json'

module Budgea

  class Client
    attr_accessor :client_id
    attr_accessor :client_secret
    attr_accessor :access_token
    attr_writer :access_token_type
    def access_token_type
      @access_token_type || 'bearer'
    end

    def initialize(domain, _settings = {})
      @settings = {
                            :authorization_endpoint => '/auth/share/',
                            :token_endpoint         => '/auth/token/access',
                            :code_endpoint          => '/auth/token/code',
                            :base_url               => "https://#{domain}/2.0",
                            :http_headers           => {},
                            :client_id              => nil,
                            :client_secret          => nil,
                            :access_token_param_name=> 'token'
                      }.merge(_settings)
    end

    def handle_callback(params={})
      if params['error']
        raise Exception.new('Authentication failed')
      end
      if !params.has_key?('code')
        return false
      end
      new_params = { :code => params['code'], :redirect_uri => @settings[:redirect_uri], :grant_type => 'authorization_code' }
      uri = URI.parse(@settings[:base_url] + @settings[:token_endpoint])
      #::RestClient.proxy = 'http://localhost:8888'
      resource = ::RestClient::Resource.new uri.to_s, @settings[:client_id], @settings[:client_secret]
      response = resource.post(new_params)

      raise Exception.new('Can’t reach remote URI') unless response.code == 200

      json_response = JSON.parse response.to_str
      @access_token = json_response['access_token']
      @access_token_type = json_response['token_type']
      params[:state] || true
    end

    def get_authentication_url(state = '')
      query_string_params = {
                              :response_type => 'code',
                              :client_id     => @settings[:client_id],
                              :redirect_uri  => @settings[:redirect_uri],
                              :state         => state
                            }
      uri = URI.parse("#{@settings[:base_url]}#{@settings[:authorization_endpoint]}")
      uri.query = URI.encode_www_form(query_string_params)
      uri.to_s
    end

    def get_settings_url(state = '')
      code_endpoint_response = JSON.parse(get(@settings[:code_endpoint]))
      query_string_params = {
                              :response_type => 'code',
                              :client_id     => @settings[:client_id],
                              :redirect_uri  => @settings[:redirect_uri],
                              :state         => state,
                              :code          => code_endpoint_response['code']
                            }
      uri = URI.parse("#{@settings[:base_url]}#{@settings[:authorization_endpoint]}")
      uri.query = URI.encode_www_form(query_string_params)
      uri.to_s
    end

    def get(uri, params = {})
      fetch(uri, params)
    end

    def fetch(uri, params, method = :get, http_headers = {})
      http_headers.merge!(@settings[:http_headers])
      #http_headers.merge!({:content_type => :json, :accept => :json})
      http_headers.merge!({:accept => :json})

      if @access_token
        case @access_token_type
        when 'Url'
          raise ArgumentException.new("You need to give parameters as Hash if you want to give the token within the URI.") unless params.is_a?(Hash)
          params[@access_token_param_name] = @access_token
        when 'Bearer'
          http_headers['Authorization'] = "Bearer #{@access_token}"
        when 'OAuth'
          http_headers['Authorization'] = "OAuth #{@access_token}"
        else
          raise ArgumentError.new("Invalid access token type: #{@access_token_type}")
        end
      end
      #RestClient.proxy = 'http://localhost:8888'
      ressource = RestClient::Resource.new uri.to_s
      response = nil
      begin
      if method == :get
        final_params = params.merge(http_headers)
        response = ressource.send(method, params.merge(final_params))
      else
        response = ressource.send(method, params, http_headers)
      end
      rescue RestClient::Exception => e
        return JSON.parse(e.response.to_str)
      end
      return JSON.parse(response.to_str)
    end

    def get_accounts(expand = nil)
      ret = get(@settings[:base_url] + '/users/me/accounts')
      return(ret['accounts']) if ret['accounts']
      ret
    end

    def get_transactions(account_id = nil)
      ret = if account_id
        get(@settings[:base_url] + "/users/me/accounts/#{account_id}/transactions", {'expand' => 'category'})
      else
        get(@settings[:base_url] + "/users/me/transactions/", {'expand' => 'category'})
      end
      ret['transactions'] ? ret['transactions'] : ret
    end

  end
end
