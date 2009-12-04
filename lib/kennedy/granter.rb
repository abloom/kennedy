require 'kennedy/ticket'

module Kennedy
  # Granter is used to authenticate credentials and grant tickets to services
  # once a client has been authenticated.
  class Granter

    # @param [Hash] args The arguments to create the granter with
    # @option args [String] :iv The AES-256 initialization vector to use for encryption and decryption
    # @option args [String] :passphrase The AES-256 passphrase to use for encryption and decryption
    # @option args [Object] :backend An instance of a backend to use for authentication
    def initialize(args = {})
      @iv = args[:iv] || raise(ArgumentError, "Encryption IV must be given as :iv")
      @passphrase = args[:passphrase] || raise(ArgumentError, "Encryption passphrase must be given as :passphrase")
      @backend = args[:backend] || raise(ArgumentError, "Authentication backend must be given as :backend")
    end
    
    # @param [Hash] args The arguments to authenticate with
    # @option args [String] :identifier The identifier (email address, for example) to use for authentication
    # @option args [String] :password The password to use for authentication
    # @return [true, false] A boolean indication of whether authentication was successful or not
    def authenticate(args = {})
      !!@backend.authenticate(args[:identifier], args[:password])
    end
    
    # @param [Hash] args The arguments to generate the ticket with
    # @option args [String] :identifier The identifier (email address, for example) the ticket grants access for
    # @return [Kennedy::Ticket] A Kennedy::Ticket object
    def generate_ticket(args = {})
      identifier = args[:identifier] || raise(ArgumentError, "An identifier must be given as :identifier")
      new_ticket(identifier)
    end
  
  private

    def new_ticket(identifier)
      Kennedy::Ticket.new(:identifier => identifier)
    end

  end # Granter
end
