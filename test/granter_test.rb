require 'teststrap'
require 'digest/sha1'

context "kennedy granter" do

  should "raise an exception if not given an IV" do
    Kennedy::Granter.new(:passphrase => Digest::SHA1.hexdigest(Time.now.to_i.to_s),
                         :backend    => Object.new) 
  end.raises(ArgumentError, "Encryption IV must be given as :iv")
  
  should "raise an exception if not given a passphrase" do
    Kennedy::Granter.new(:iv      => Digest::SHA1.hexdigest(Time.now.to_i.to_s),
                         :backend => Object.new)
  end.raises(ArgumentError, "Encryption passphrase must be given as :passphrase")

  should "raise an exception if not given a backend" do
    Kennedy::Granter.new(:iv         => Digest::SHA1.hexdigest(Time.now.to_i.to_s),
                         :passphrase => Digest::SHA1.hexdigest(Time.now.to_i.to_s))
  end.raises(ArgumentError, "Authentication backend must be given as :backend")
  
  context "with valid arguments and a given backend" do
    
    setup do
      @granter = Kennedy::Granter.new(:iv         => Digest::SHA1.hexdigest(Time.now.to_i.to_s),
                                      :passphrase => Digest::SHA1.hexdigest(Time.now.to_i.to_s),
                                      :backend    => @backend = StubBackend.new)
    end

    should "use the given backend to authenticate" do
      @granter.authenticate(:identifier => "foo", :password => "bar")
      @backend.credentials
    end.equals(["foo", "bar"])
    
    should "return true with valid credentials" do
      @granter.authenticate(:identifier => "foo", :password => "bar") == true
    end

    should "return false with invalid credentials" do
      @granter.authenticate(:identifier => "foo", :password => "baz") == false
    end
    
  end # with valid arguments and a given backend

  context "generating a ticket for a service" do
    context "with default expiry time" do
      setup do
        @granter = Kennedy::Granter.new(:iv         => Digest::SHA1.hexdigest(Time.now.to_i.to_s),
                                        :passphrase => Digest::SHA1.hexdigest(Time.now.to_i.to_s),
                                        :backend    => @backend = StubBackend.new)
      end
      
      should "require an identifier to generate a ticket" do
        @granter.generate_ticket
      end.raises(ArgumentError, "An identifier must be given as :identifier")
      
      should "return a ticket object when granting" do
        @granter.generate_ticket(:identifier => "foo@example.com")
      end.kind_of(Kennedy::Ticket)

    end # with default expiry time
  end   # generating a ticket for a service

end

