require 'teststrap'

context "kennedy ldap backend" do

  should "require a :host argument" do
    Kennedy::Backends::LDAP.new(:auth => {}, :base => "cn=foo")
  end.raises(ArgumentError, "Host must be given as :host")

  should "require an :auth argument" do
    Kennedy::Backends::LDAP.new(:host => "example.com", :base => "cn=foo")
  end.raises(ArgumentError, "Auth must be given as :auth")

  should "require a :base argument" do
    Kennedy::Backends::LDAP.new(:host => "example.com", :auth => {})
  end.raises(ArgumentError, "Base must be given as :base")

  should "raise if no filter block is given and authentication is attempted" do
    backend = Kennedy::Backends::LDAP.new(:host => "example.com", :auth => {}, :base => "foo")
    backend.authenticate("foo", "bar")
  end.raises(ArgumentError, "Set a filter block on this object using the 'filter' writer")

  context "trying to authenticate" do
    
    setup do
      @backend = Kennedy::Backends::LDAP.new(:host => "example.com", :auth => {}, :base => "foo")
      @backend.filter = lambda do |identifier|
        "(mail=#{identifier})"
      end
      ldap_conn = nil
      @backend.instance_eval { ldap_conn = @ldap_conn = StubLDAP.new(nil) } 
      ldap_conn
    end

    should "use the given filter block to generate the search filter" do
      @backend.authenticate("foo@example.com", "bar")
      topic.bind_as_arguments[:filter]
    end.equals("(mail=foo@example.com)")
    
    should "use the given password to bind as" do
      @backend.authenticate("foo@example.com", "bar")
      topic.bind_as_arguments[:password]
    end.equals("bar")
    
    context "succesfully" do
      setup do
        @backend.instance_eval { @ldap_conn = StubLDAP.new(Object.new) } 
      end

      should "return true when the backend returns a non-nil value" do
        @backend.authenticate("foo@example.com", "bar") == true
      end
    end

    context "unsuccesfully" do
      setup do
        @backend.instance_eval {  @ldap_conn = StubLDAP.new(nil) } 
      end

      should "return false when the backend returns nil" do
        @backend.authenticate("foo@example.com", "bar") == false
      end
    end

  end

end
