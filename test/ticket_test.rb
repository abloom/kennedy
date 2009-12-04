require 'teststrap'
require 'digest/sha1'

context "kennedy ticket" do
  should "not allow calling new" do
    Kennedy::Ticket.new
  end.raises(NoMethodError)

  context "creating a new ticket" do
    should "raise an exception if not given an identifier" do
      Kennedy::Ticket.create({})
    end.raises(ArgumentError, "Ticket identifier must be given as :identifier")
  
    should "raise an exception if no IV is given" do
      Kennedy::Ticket.create(:identifier => "foo@example.com", :passphrase => "foo")
    end.raises(ArgumentError, "Ticket encryption IV must be given as :iv")

    should "raise an exception if no passphrase is given" do
      Kennedy::Ticket.create(:identifier => "foo@example.com", :iv => "foo")
    end.raises(ArgumentError, "Ticket encryption passphrase must be given as :passphrase")
    
    should "be encryptable with all args given" do
      ticket = Kennedy::Ticket.create(:identifier => "foo@example.com", :iv => Digest::SHA1.hexdigest(Time.now.to_i.to_s),
                                                                        :passphrase => Digest::SHA1.hexdigest(Time.now.to_i.to_s))
      ticket.to_encrypted
    end.kind_of(String)
  end # building a new ticket

  context "reading in an encrypted ticket" do
    
    should "raise an exception if no IV is given" do
      Kennedy::Ticket.from_encrypted(:data => "foo", :passphrase => "foo")
    end.raises(ArgumentError, "Ticket encryption IV must be given as :iv")

    should "raise an exception if no passphrase is given" do
      Kennedy::Ticket.from_encrypted(:data => "foo", :iv => "foo")
    end.raises(ArgumentError, "Ticket encryption passphrase must be given as :passphrase")
    
    should "raise an exception if no data is given" do
      Kennedy::Ticket.from_encrypted(:iv => "foo", :passphrase => "bar")
    end.raises(ArgumentError, "Data must be given as :data")

    context "with valid encryption credentials" do
      setup do
        iv, passphrase = Digest::SHA1.hexdigest(Time.now.to_i.to_s), Digest::SHA1.hexdigest(Time.now.to_i.to_s)
        ticket = Kennedy::Ticket.create(:identifier => "foo@example.com", :iv         => iv,
                                                                          :passphrase => passphrase)
        encrypted = ticket.to_encrypted
        decrypted = Kennedy::Ticket.from_encrypted(:data => encrypted, :iv => iv, :passphrase => passphrase)
      end

      should "not be expired" do
        !topic.expired?
      end

      should "contain the identifier" do
        topic.identifier
      end.equals("foo@example.com")
    end # with valid encryption credentials

    context "with a gibberish ticket" do
      should "raise Kennedy::BadTicketException" do
        Kennedy::Ticket.from_encrypted(:data => "bzzt", :iv => Digest::SHA1.hexdigest(Time.now.to_i.to_s),
                                                        :passphrase => Digest::SHA1.hexdigest(Time.now.to_i.to_s))
      end.raises(Kennedy::BadTicketException)
    end

    context "with an expired ticket" do
      setup do
        iv, passphrase = Digest::SHA1.hexdigest(Time.now.to_i.to_s), Digest::SHA1.hexdigest(Time.now.to_i.to_s)
        ticket = Kennedy::Ticket.create(:identifier => "foo@example.com", :iv         => iv, :expiry => -30,
                                                                          :passphrase => passphrase)
        encrypted = ticket.to_encrypted
        decrypted = Kennedy::Ticket.from_encrypted(:data => encrypted, :iv => iv, :passphrase => passphrase)
      end

      should "be expired" do
        topic.expired?
      end
    end
  end   # reading in an encrypted ticket
end


