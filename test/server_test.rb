require 'teststrap'
require 'kennedy/server'
require 'digest/sha1'
require 'base64'

context "kennedy server" do
  iv =  Digest::SHA1.hexdigest("what")
  passphrase =  Digest::SHA1.hexdigest("qhat")
  session_secret = "foobarbaz"

  new_backend = lambda do
    StubBackend.new
  end

  new_server = lambda do 
    Kennedy::Server.create(:encryption => {:iv => iv, :passphrase => passphrase},
                           :backend    => new_backend, :session_secret => "foobarbaz",
                           :api_keys => {'foo@example.com' => 'password'})
  end

  encode_credentials = lambda do |username,password|
    "Basic " + Base64.encode64("#{username}:#{password}")
  end
  
  should "use tamper-proof cookies" do
    new_server[].middleware.detect do |mw|
      mw[0] == Rack::Session::Cookie && !mw[1][0][:secret].nil?
    end
  end

  context "delete to /session" do
    setup do
      @server = Rack::MockRequest.new(new_server[])
    end

    should "not allow non-ssl connections" do
      @server.delete('/session').status
    end.equals(403)

    context "via ssl" do
      setup do
        @server = SSLMockRequest.new(new_server[])
        @server.delete('/session', 'CONTENT_TYPE' => 'application/json')
      end
      
      should "return a 200" do
        topic.status
      end.equals(200)

      should "return success" do
        JSON.parse(topic.body)['success']
      end.equals('session_destroyed')

    end
  end

  context "post to /session" do
    setup do
      @server = Rack::MockRequest.new(new_server[])
    end

    should "not allow non-ssl connections" do
      @server.post('/session').status
    end.equals(403)

    context "via ssl" do  
      setup do
        @server = SSLMockRequest.new(new_server[])
      end
      
      should "not allow non-JSON requests" do
        @server.post('/session').status
      end.equals(415)
      
      context "with invalid credentials" do
        setup do
          @server.post('/session', 'CONTENT_TYPE' => 'application/json', :input => {}.to_json)
        end

        should "return a 406" do
          topic.status
        end.equals(406)
        
        should "return json" do
          topic.content_type
        end.equals("application/json")
        
        should "return an error" do
          JSON.parse(topic.body)['error']
        end.equals('bad_credentials')

      end

      context "with valid credentials" do
        setup do
          @server.post('/session', 'CONTENT_TYPE' => 'application/json', :input => {'credentials' => {'identifier' => 'foo', 'password' => 'bar'}}.to_json)
        end

        should "return a 201" do
          topic.status
        end.equals(201)
        
        should "return json" do
          topic.content_type
        end.equals("application/json")

        should "return success" do
          JSON.parse(topic.body)['success']
        end.equals('session_created')
        
        should "set a session cookie" do
          topic.headers['Set-Cookie']
        end.matches(/rack\.session=/)
        
      end
    end 

  end # post to /session
  
  context "get to /session" do
    setup do
      @server = Rack::MockRequest.new(new_server[])
    end

    should "not allow non-ssl connections" do
      @server.get('/session').status
    end.equals(403)
    
    context "via ssl" do  
      setup do
        @server = SSLMockRequest.new(new_server[])
      end
      
      should "not allow non-JSON requests" do
        @server.get('/session').status
      end.equals(415)
      
      context "when already logged in" do
        setup do
          response = @server.post('/session', 'CONTENT_TYPE' => 'application/json', :input => {'credentials' => {'identifier' => 'foo', 'password' => 'bar'}}.to_json)
          cookie = response.headers['Set-Cookie'].split(";").first
          @server.get('/session', 'CONTENT_TYPE' => 'application/json', 'HTTP_COOKIE' => cookie)
        end
        
        should "return json" do
          topic.content_type
        end.equals("application/json")

        should "respond with a ticket" do
          JSON.parse(topic.body)['ticket']
        end.kind_of(String)

      end # when already logged in

      context "when not logged in" do
        setup do
          @server.get('/session', 'CONTENT_TYPE' => 'application/json')
        end
        
        should "return json" do
          topic.content_type
        end.equals("application/json")
        
        should "return a 401" do
          topic.status
        end.equals(401)
      
      end # when not logged in
    end # via ssl
  end # get to /session
  
  context "post to /validation_request" do
    setup do
      @server = Rack::MockRequest.new(new_server[])
    end

    should "not allow non-ssl connection" do
      @server.post('/validation_request').status
    end.equals(403)
    
    context "via ssl" do
      setup do
        @server = SSLMockRequest.new(new_server[])
      end

      should "not allow non-JSON requests" do
        @server.post('/validation_request').status
      end.equals(415)
     
      context "with no API key" do
        setup do
          @server.post('/validation_request', 'CONTENT_TYPE' => 'application/json', :input => {'ticket' => '123'}.to_json)
        end
        
        should "return a 401" do
          topic.status
        end.equals(401)

        should "return an error" do
          JSON.parse(topic.body)['error']
        end.equals('authentication_required')
      end

      context "with a bad API key" do

        setup do
          @server.post('/validation_request', 'CONTENT_TYPE' => 'application/json', 'HTTP_AUTHORIZATION'=> encode_credentials['foo@example.com', 'badpassword'],
                       :input => {'ticket' => '123'}.to_json)
        end
        
        should "return a 401" do
          topic.status
        end.equals(401)

        should "return an error" do
          JSON.parse(topic.body)['error']
        end.equals('authentication_required')

      end

      context "with a valid ticket" do
        setup do
          granter = Kennedy::Granter.new(:iv => iv, :passphrase => passphrase, :backend => StubBackend.new)
          ticket = granter.generate_ticket(:identifier => "foo@example.com")
          @server.post('/validation_request', 'CONTENT_TYPE' => 'application/json', 'HTTP_AUTHORIZATION'=> encode_credentials['foo@example.com', 'password'],
                       :input => {'ticket' => Base64.encode64(ticket.to_encrypted)}.to_json)
        end

        should "return json" do
          topic.content_type
        end.equals("application/json")

        should "return a 200" do
          topic.status
        end.equals(200)
        
        should "return an identifier" do
          JSON.parse(topic.body)['identifier']
        end.equals('foo@example.com')

      end
      
      context "with gibberish" do
        setup do
          @server.post('/validation_request', 'CONTENT_TYPE' => 'application/json', 'HTTP_AUTHORIZATION'=> encode_credentials['foo@example.com', 'password'],
                       :input => {'ticket' => 'bzzt'}.to_json)
        end

        should "return json" do
          topic.content_type
        end.equals("application/json")

        should "return a 406" do
          topic.status
        end.equals(406)
        
        should "return an error" do
          JSON.parse(topic.body)['error']
        end.equals('bad_ticket')

      end

      context "with an expired ticket" do
        setup do
          ticket = Kennedy::Ticket.create(:identifier => "foo@example.com", :iv => iv, :expiry => -30, :passphrase => passphrase)
          @server.post('/validation_request', 'CONTENT_TYPE' => 'application/json', 'HTTP_AUTHORIZATION'=> encode_credentials['foo@example.com', 'password'],
                       :input => {'ticket' => Base64.encode64(ticket.to_encrypted)}.to_json)
        end
        
        should "return json" do
          topic.content_type
        end.equals("application/json")

        should "return a 406" do
          topic.status
        end.equals(406)

        should "return an error" do
          JSON.parse(topic.body)['error']
        end.equals('expired_ticket')
      end
    end # via ssl
  end
end

