module Kennedy
  module Backends
    class LDAP
      attr_writer :filter

      # Creates a new LDAP auth backend with the given arguments
      # @param [Hash] args The arguments to construct the backend with
      # @option args [String] :host The LDAP server host to connect to
      # @option args [Hash]   :auth The auth method ruby-net-ldap should use
      # @option args [String] :base The treebase to check against
      def initialize(args = {})
        @host = args[:host] || raise(ArgumentError, "Host must be given as :host")
        @auth = args[:auth] || raise(ArgumentError, "Auth must be given as :auth")
        @base = args[:base] || raise(ArgumentError, "Base must be given as :base")
        @filter = lambda { raise(ArgumentError, "Set a filter block on this object using the 'filter' writer") }
      end
      
      # Authenticates the given credentials against LDAP
      # @param [String] identifier The identifier to filter on
      # @param [String] password The password to use
      # @return [true, false] A boolean indicating authentication success
      def authenticate(identifier, password)
        filter_string = @filter.call(identifier)
        !!ldap_conn.bind_as(:filter => filter_string, :password => password)
      end
    
    private

      def ldap_conn
        @ldap_conn ||= Net::LDAP.new(:host => @host, :auth => @auth, :base => @base)
      end

    end # LDAP
  end   # Backends
end     # Kennedy
