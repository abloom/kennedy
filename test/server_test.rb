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
  
end

