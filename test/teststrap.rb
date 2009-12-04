require 'rubygems'
require 'riot'
require 'kennedy'

class StubBackend
  attr_reader :credentials
  def authenticate(identifier, password)
    @credentials = [identifier, password]
    password == 'bar'
  end
end
