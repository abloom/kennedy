require 'sinatra/base'
require 'json'
require 'base64'
require 'rack/session/cookie'
require 'kennedy'

module Kennedy
  class Server < Sinatra::Base
    disable :session
    
    # Creates a new subclass of Kennedy::Server with the given options
    # @param [Hash] opts The options to use when building the subclass
    # @option opts [Hash]   :encryption     The IV and passphrase to use when generating tickets, given as
    #                                       :iv and :passphrase keys in a Hash.
    # @option opts [Object] :backend        An instance of a backend to use for authentication.
    # @option opts [String] :session_secret A secret for Rack::Session::Cookie to use when generating session
    #                                       cookies.
    # @option opts [Hash]   :api_keys       A hash of key-value pairs to use as API users/keys with HTTP basic
    #                                       authentication
    #                    
    def self.create(opts = {})
      sc = Class.new(self)
      sc.instance_eval do
        opts.each { |k,v| set k.to_sym, v }
        raise ArgumentError, "A session secret must be set with :session_secret" unless defined?(session_secret)
        add_cookie_middleware
        set :api_keys, (defined?(api_keys) ? api_keys : {})
        set :require_ssl, (defined?(require_ssl) ? require_ssl : true)
      end
    end
    
    # Ensures all connections come in over SSL
    before do
      next unless require_ssl?
      unless (request.env['HTTP_X_FORWARDED_PROTO'] || request.env['rack.url_scheme']) == 'https'
        halt 403, "Only SSL connections are accepted."
      end
    end
    
    # Ensures all connections come in requesting JSON
    before do
      unless request.content_type == 'application/json'
        halt 415, "Only JSON requests are accepted."
      end
    end
    
    # Parses request body as JSON
    before do
      begin
        @json = JSON.parse(request.body.read)
      rescue
        @json = {}
      end
    end
    
    # Takes incoming requests with a 'ticket' property in the JSON body and decrypts the ticket,
    # returning an identifier as the 'identifier' property in the JSON response body if the
    # ticket is valid and unexpired.
    post "/validation_request" do
      content_type "application/json"
      require_api_authentication
      begin
        encrypted_ticket = Base64.decode64(@json['ticket'])
        ticket = granter.read_ticket(:data => encrypted_ticket)
        if ticket.expired?
          [406, {'error' => 'expired_ticket'}.to_json]
        else
          [200, {'identifier' => ticket.identifier}.to_json]
        end
      rescue => e
        [406, {'error' => 'bad_ticket'}.to_json]
      end
    end

    # Takes incoming requests and generates an encrypted and Base64 encoded ticket in the 'ticket'
    # property of the JSON response if the user has a valid session.
    get '/session' do
      content_type "application/json"
      if session['identifier']
        ticket = granter.generate_ticket(:identifier => session['identifier'])
        [200, {'ticket' => Base64.encode64(ticket.to_encrypted)}.to_json]
      else
        [401, {'error' => 'authentication_required'}.to_json]
      end
    end
    
    # Creates a session if authentication with the given credentials passed as 'identifier' and
    # 'password' in the JSON body is successful.
    post '/session' do
      credentials = @json['credentials']
      content_type "application/json"
      if credentials.nil? || !granter.authenticate(:identifier => credentials['identifier'], :password => credentials['password'])
        [406, {'error' => 'bad_credentials'}.to_json]
      else
        session['identifier'] = credentials['identifier']
        [201, {'success' => 'session_created'}.to_json]
      end
    end
    
    # Destroys an existing session.
    delete '/session' do
      request.session.clear
      [200, {'success' => 'session_destroyed'}.to_json]
    end

  private
    
    def auth
      @auth ||= Rack::Auth::Basic::Request.new(request.env)
    end

    def authorized?
      request.env['REMOTE_USER']
    end
    
    def unauthorized!(realm = "Kennedy")
      headers 'WWW-Authenticate' => %(Basic realm="#{realm}")
      throw :halt, [401, {'error' => 'authentication_required'}.to_json]
    end

    def bad_request!
      throw :halt, [400, {'error' => 'bad_request'}.to_json]
    end
    
    def authorize(username, password)
      api_keys.has_key?(username) && api_keys[username] == password
    end

    def require_api_authentication
      return if authorized?
      unauthorized! unless auth.provided?
      bad_request! unless auth.basic?
      unauthorized! unless authorize(*auth.credentials)
      request.env['REMOTE_USER'] = auth.username
    end

    def self.add_cookie_middleware
      use Rack::Session::Cookie, :secret => session_secret
    end
    
    def granter
      @granter ||= Kennedy::Granter.new(:iv => encryption[:iv], :passphrase => encryption[:passphrase],
                                        :backend => backend)
    end

    def encryption
      self.class.encryption
    end

    def backend
      self.class.backend
    end
    
    def api_keys
      self.class.api_keys
    end
    
    def require_ssl?
      !!options.require_ssl
    end

  end # Server
end   # Kennedy

