require_relative '../custom_log_formatter'

class QboApi
  attr_accessor :offline_job_id, :intuit_appid, :intuit_app_secret

  IDENTITY_INTERNAL_URL = (ENV['IDENTITY_INTERNAL_ENDPOINT'] || 'https://identityinternal.api.intuit.com/v1/graphql')
  IDENTITY_URL = (ENV['IDENTITY_ENDPOINT'] || 'https://identity.api.intuit.com/v2/graphql')

  def offline_token
    @offline_token || generate_offline_token
  end

  def offline_headers
    if @offline_headers.present? && @offline_headers["expiry"] > Time.now
      return @offline_headers
    end
    generate_headers_for_offline_token
  end

  def offline_token=(token)
    @offline_token = token
  end

  def offline_headers=(offline_header)
    @offline_headers = offline_header
  end

  def i_am_client_connection(url, authorization)
    headers = { 'Accept' => 'application/json',
                'Content-Type' => 'application/json',
                'intuit_tid' => intuit_tid }
    Faraday.new(url: url) { |conn|
      conn.headers.update(headers) if headers
      conn.authorization(authorization[:type], authorization[:value]) if authorization
      add_exception_middleware(conn)
      add_connection_adapter(conn)
      conn.response :logger, QboApi.logger, :errors => true,  formatter: CustomLogFormatter if QboApi.log
      middleware.apply(conn) do
        yield conn if block_given?
      end
    }
  end

  def generate_headers_for_offline_token
    begin
      authorization = { :type => :Intuit_IAM_Authentication,
                        :value => { intuit_appid: intuit_appid,
                                    intuit_app_secret: intuit_app_secret}}
      connection = i_am_client_connection(IDENTITY_INTERNAL_URL, authorization)
      resp = connection.post do |req|
        req.body = {
          query: "mutation identitySignInInternalApplicationWithPrivateAuth($input: Identity_SignInApplicationWithPrivateAuthInput!) {\n    identitySignInInternalApplicationWithPrivateAuth(input: $input) {\n authorizationHeader \n accessToken { \n expiresInSeconds \n} \n} \n}",
          variables: {
            input: {
              profileId: offline_job_id
            }
          }
        }.to_json
      end
      self.offline_headers = parse_identity_response(resp)
    rescue => error
      retry_count = handle_error(error, retry_count)
      retry
    end
  end

  def generate_offline_token
    begin
      authorization = { :type => nil,
                        :value => "#{offline_headers["header"]},intuit_appid=#{intuit_appid},intuit_app_secret=#{intuit_app_secret}"}
      connection = i_am_client_connection(IDENTITY_URL, authorization)
      resp = connection.post do |req|
        req.body = {
          "query": "mutation identityImpersonateAccount($input: Identity_ImpersonateAccountInput!) {\n    identityImpersonateAccount(input: $input) {\n        authorizationHeader\n    }\n}",
          "variables": {
            "input": {
              "accountId": realm_id
            }
          }
        }.to_json
      end
      self.offline_token = parse_identity_response(resp)
    rescue => error
      retry_count = handle_error(error, retry_count)
      retry
    end
  end

  def handle_error(error, retry_count)
    if error.is_a?(QboApi::Unauthorized)
      retry_count ||= 0
      if retry_count < 2
        return retry_count += 1
      end
    end
    #raise error if not unauthorizied or retry limit is reached
    raise error
  end

  def parse_identity_response(resp)
    authorizationHeader=nil
    data = parse_response_body(resp)
    if(data["data"].present?)
      if(data["data"]["identitySignInInternalApplicationWithPrivateAuth"].present?)
        authorizationHeader={}
        authorizationHeader["header"]= data["data"]["identitySignInInternalApplicationWithPrivateAuth"]["authorizationHeader"]
        expiry_in_seconds = data["data"]["identitySignInInternalApplicationWithPrivateAuth"]["accessToken"]["expiresInSeconds"]
        authorizationHeader["expiry"]= Time.now + expiry_in_seconds.to_i.seconds
      elsif(data["data"]["identityImpersonateAccount"].present?)
        authorizationHeader = data["data"]["identityImpersonateAccount"]["authorizationHeader"]
      end
    end
    raise QboApi::Unauthorized if !authorizationHeader.present?
    authorizationHeader
  end

  module Connection::IAmClient

    def self.included(*)
      QboApi::Connection.add_authorization_middleware :i_am_client
      super
    end

    def default_attributes
      super.merge!(
        offline_job_id: defined?(OFFLINE_JOB_ID) ? OFFLINE_JOB_ID : nil,
        intuit_appid: defined?(INTUIT_APPID) ? INTUIT_APPID : nil,
        intuit_app_secret: defined?(INTUIT_APP_SECRET) ? INTUIT_APP_SECRET : nil,
        )
    end

    def add_i_am_client_authorization_middleware(conn)
      conn.use FaradayMiddleware::IAmClientRefresh, self
      conn.authorization(nil, "#{offline_token},intuit_appid=#{intuit_appid},intuit_app_secret=#{intuit_app_secret}")
    end

    def use_i_am_client_middleware?
      offline_token
    end

  end

end

# @private
module FaradayMiddleware
  # @private
  class IAmClientRefresh < Faraday::Middleware
    DEFAULT_ATTEMPT_LIMIT = 5

    def call(env)
      begin
        @app.call(env).tap do |resp|
          raise QboApi::Unauthorized if resp.status == 401
        end
      rescue QboApi::Unauthorized => error
        #put retry based on count
        @retry_count ||= 0
        if @retry_count <= DEFAULT_ATTEMPT_LIMIT
          @qbo_api.generate_offline_token
          @retry_count += 1
          retry
        else
          raise error
        end
      end
    end

    def initialize(app, qbo_api)
      @qbo_api = qbo_api
      super app
    end

    #
    # private
    #
    # def attempt_limit
    #   if ENV['QBO_OAUTH2_REFRESH_ATTEMPT_LIMIT']
    #     ENV['QBO_OAUTH2_REFRESH_ATTEMPT_LIMIT']
    #   else
    #     DEFAULT_ATTEMPT_LIMIT
    #   end.to_i
    # end

  end
end