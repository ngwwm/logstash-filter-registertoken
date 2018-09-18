# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require "jwt"

# This filter is created base on the example from github. It will
# generate a json web token from the given payload and base64 coded
# it. The enocded token will be add the the event 'token' field.
#
class LogStash::Filters::RegisterToken < LogStash::Filters::Base

  # Setting the config_name here is required. This is how you
  # configure this filter from your Logstash config.
  #
  # filter {
  #   registertoken {
  #     "field1" => "value1"
  #     "field2" => "value2"
  #     ...
  #   }
  #   secret => "mysecret"
  #   alg => "HS256"
  # }
  #
  config_name "registertoken"

  # Parameters
  config :payload, :validate => :hash, :default => {}
  config :secret, :validate => :string, :required => true
  config :alg, :validate => :string, :default => "HS256"

  #time lapsed before the token expired, default to 4 hours
  config :lapse, :validate => :number, :default => 14400

  public
  def register
    # Add instance variables
  end # def register

  public
  def filter(event)

    if @payload
      # Generate JWT from the payload and base64 encoded it.

      # Read all fields passed in and put it in a new hash
      @payload.each do |field, value|
        @logger.debug? && @logger.debug("payload: ", :field => event.sprintf(field), :value => event.sprintf(value) )
        payload.store(event.sprintf(field), event.sprintf(value)) 
      end
      
      #work out the token expired time
      exp = Time.now.to_i + lapse 
      
      payload.store("exp", exp)
      
      @logger.debug? && @logger.debug("payload: ", :payload => payload)
      
      #payload = LogStash::Json.load(event.sprintf(@payload))
      #payload = event.sprintf(@payload).to_json

      # using the event.set API
      event.set("token",  Base64.urlsafe_encode64(JWT.encode payload, @secret, @alg))

      # correct debugging log statement for reference
      # using the event.get API
      @logger.debug? && @logger.debug("token is now: #{event.get("token")}")
    end

    # filter_matched should go in the last line of our successful code
    filter_matched(event)
  end # def filter
end # class LogStash::Filters::RegisterToken
