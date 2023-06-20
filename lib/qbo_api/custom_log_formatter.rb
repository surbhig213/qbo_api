require 'faraday'
require 'faraday/logging/formatter'

class QboApi
  class CustomLogFormatter < Faraday::Logging::Formatter

    def request(env)
      # Build a custom message using `env`
      log_message = "#{LOG_TAG} request_method=#{env.method}, request_url=#{env.url}, intuit_tid=#{env.request_headers["intuit_tid"]}"
      info('Request') { log_message }
    end

    def response(env)
      # Build a custom message using `env`
      log_message = "#{LOG_TAG} response_status=#{env.status}, intuit_tid=#{env.request_headers["intuit_tid"]}"
      info('Response') { log_message }
    end

    def exception(exc)
      # Build a custom message using `exc`
      # log_message = "status=#{env.status}, intuit_tid=#{env.request_headers["intuit_tid"]}"
      info('Error') { "#{LOG_TAG} Error Raised: #{exc}" }
    end

  end
end