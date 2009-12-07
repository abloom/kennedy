require 'openssl'
require 'json'
require 'time'

module Kennedy
  class BadTicketException < RuntimeError; end

  # A ticket represents a time-constrained period in which an authenticated
  # person can access a service
  class Ticket
    DefaultExpiry = 30 # In seconds
    attr_reader :identifier

    class << self
      private :new
    end

    # Creates a new ticket with the given arguments
    # @param [Hash] args The arguments to generate the ticket with
    # @option args [String] :identifier An identifier to use in the ticket
    # @option args [String] :iv An iv to use to encrypt and decrypt the ticket
    # @option args [String] :passphrase A passphrase to encrypt and decrypt the ticket
    # @option args [String] :expiry A length of time in seconds for which this ticket is valid
    #                               after to_encrypted is called
    def self.create(args = {})
      identifier = args[:identifier] || raise(ArgumentError, "Ticket identifier must be given as :identifier")
      ticket = new(:iv => args[:iv], :passphrase => args[:passphrase], :expiry => args[:expiry])
      ticket.identifier = identifier
      ticket
    end
    
    # Decrypts a ticket from the given arguments
    # @param [Hash] args The arguments to build the ticket with
    # @option args [String] :data An encrypted ticket
    # @option args [String] :iv An IV to use to decrypt the ticket
    # @option args [String] :passphrase A passphrase to use to decrypt the ticket
    def self.from_encrypted(args = {})
      data = args[:data] || raise(ArgumentError, "Data must be given as :data")
      ticket = new(:iv => args[:iv], :passphrase => args[:passphrase])
      ticket.decrypt(data)
      ticket
    end

    # @param [Hash] args The arguments to construct the ticket with
    # @option args [String] :iv An iv to use to encrypt and decrypt the ticket
    # @option args [String] :passphrase A passphrase to encrypt and decrypt the ticket
    def initialize(args = {})
      @iv = args[:iv] || raise(ArgumentError, "Ticket encryption IV must be given as :iv")
      @passphrase = args[:passphrase] || raise(ArgumentError, "Ticket encryption passphrase must be given as :passphrase")
      @expiry = args[:expiry] || DefaultExpiry
    end
    
    def identifier=(identifier)
      @identifier ||= identifier
    end

    # Generates an encrypted chunk of JSON with the identifier and expiration time for this
    # ticket encoded in
    # @return [String] An encrypted JSON string
    def to_encrypted
      cipher = OpenSSL::Cipher::Cipher.new("aes-256-cbc")
      cipher.encrypt
      cipher.key = @passphrase
      cipher.iv = @iv
      encrypted = cipher.update(to_expiring_json)
      encrypted << cipher.final
      encrypted
    end
    
    # Decrypts the given ticket data
    # @param data [String] The ticket data to decrypt
    def decrypt(data)
      cipher = OpenSSL::Cipher::Cipher.new("aes-256-cbc")
      cipher.decrypt
      cipher.key = @passphrase
      cipher.iv = @iv
      decrypted = cipher.update(data)
      decrypted << cipher.final
      json = JSON.parse(decrypted)
      self.identifier = json['identifier']
      @expiry = Time.parse(json['expiry'])
    rescue OpenSSL::Cipher::CipherError => e
      raise Kennedy::BadTicketException, "Given data was not decryptable"
    end
    
    def expired?
      !@expiry.nil? && (@expiry < Time.now)
    end

  private
    
    def to_expiring_json
      {'identifier' => @identifier, 'expiry' => Time.now + @expiry}.to_json
    end

  end # Ticket
end   # Kennedy
