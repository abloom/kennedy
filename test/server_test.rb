require 'teststrap'
require 'kennedy/server'
require 'digest/sha1'

context "kennedy server" do

  new_backend = lambda do
    StubBackend.new
  end

  new_server = lambda do 
    Kennedy::Server.create(:encryption => {:iv => Digest::SHA1.hexdigest("what"), :passphrase => Digest::SHA1.hexdigest("qhat")},
                           :backend    => new_backend)
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

end

