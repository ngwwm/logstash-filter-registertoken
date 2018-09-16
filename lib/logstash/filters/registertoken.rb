# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
#require "base64"
require "jwt"

# This example filter will replace the contents of the default
# message field with whatever you specify in the configuration.
#
# It is only intended to be used as an example.
class LogStash::Filters::RegisterToken < LogStash::Filters::Base

  # Setting the config_name here is required. This is how you
  # configure this filter from your Logstash config.
  #
  # filter {
  #   example {
  #     message => "My message..."
  #   }
  # }
  #
  config_name "registertoken"

  # Replace the message with this value.
  config :payload, :validate => :hash, :default => {}
  config :secret, :validate => :string, :required => true
  config :alg, :validate => :string, :default => "HS256"


  public
  def register
    # Add instance variables
  end # def register

  public
  def filter(event)

    if @payload
      # Replace the event message with our message as configured in the
      # config file.

      #@payload.each do |field, value|
      #  event.set(field, value)
      #end

      # using the event.set API
      #event.set("token",  Base64.urlsafe_encode64(@secret))
      event.set("token",  Base64.urlsafe_encode64(JWT.encode @payload, @secret, @alg))

      # correct debugging log statement for reference
      # using the event.get API
      @logger.debug? && @logger.debug("token is now: #{event.get("token")}")
    end

    # filter_matched should go in the last line of our successful code
    filter_matched(event)
  end # def filter
end # class LogStash::Filters::RegisterToken
