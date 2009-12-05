require 'rubygems'
require 'riot'
require 'kennedy'
require 'rack'

class StubBackend
  attr_reader :credentials
  def authenticate(identifier, password)
    @credentials = [identifier, password]
    password == 'bar'
  end
end

class StubLDAP
  attr_reader :bind_as_arguments
  def initialize(return_val)
    @return_val = return_val
  end

  def bind_as(args)
    @bind_as_arguments = args
    @return_val
  end
end

class SSLMockRequest < Rack::MockRequest
  
  def self.env_for(*args)
    env = super(*args)
    env["rack.url_scheme"] = "https"
    env
  end

end
