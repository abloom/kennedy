require 'sinatra/base'
require 'json'
require 'base64'
require 'rack/session/cookie'

module Kennedy
  class Server < Sinatra::Base
    disable :session
    
    def self.create(opts = {})
      sc = Class.new(self)
      sc.instance_eval do
        opts.each { |k,v| set k.to_sym, v }
        raise ArgumentError, "A session secret must be set with :session_secret" unless defined?(session_secret)
        add_cookie_middleware
        self
      end
    end

    configure :development do
      require 'ruby-debug'
    end
    
    configure :production do
      before do
        unless (request.env['HTTP_X_FORWARDED_PROTO'] || request.env['rack.url_scheme']) == 'https'
          halt 403, "Only SSL connections are accepted."
        end
      end
    end
    
    before do
      unless request.content_type == 'application/json'
        halt 415, "Only JSON requests are accepted."
      end
    end
    
    before do
      begin
        @json = JSON.parse(request.body.read)
      rescue
        @json = {}
      end
    end
    
    post "/validation_request" do
      content_type "application/json"
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

    get '/session' do
      content_type "application/json"
      if session['identifier']
        ticket = granter.generate_ticket(:identifier => session['identifier'])
        [200, {'ticket' => Base64.encode64(ticket.to_encrypted)}.to_json]
      else
        [401, {'error' => 'authentication_required'}.to_json]
      end
    end

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
    
    delete '/session' do
      request.session.clear
      [200, {'success' => 'session_destroyed'}.to_json]
    end

  private

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

  end # Server
end   # Kennedy

