require 'sinatra/base'
require 'json'

module Kennedy
  class Server < Sinatra::Base
    set :sessions, true
    
    def self.create(opts = {})
      Class.new(self) do
        opts.each { |k,v| set k.to_sym, v }
      end
    end

    before do
      unless (request.env['HTTP_X_FORWARDED_PROTO'] || request.env['rack.url_scheme']) == 'https'
        halt 403, "Only SSL connections are accepted."
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

