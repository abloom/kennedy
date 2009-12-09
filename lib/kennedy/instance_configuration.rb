require 'yaml'
require 'pathname'

module Kennedy
  class InstanceConfiguration
    attr_reader :backend, :encryption, :api_keys

    RequiredFiles = %w[backend.rb
                       encryption.yml
                       sessions.yml
                       api_keys.yml]

    class << self
      private :new
    end
    
    def initialize(config_dir)
      @config_dir = config_dir
      load_backend
      load_encryption
      load_sessions
      load_api_keys
    end

    def self.load_config(config_dir)
      config_dir = Pathname(config_dir)
      raise ArgumentError, "Config dir '#{config_dir}' does not exist" unless config_dir.exist?
      RequiredFiles.each do |rf|
        expected = config_dir + rf
        raise ArgumentError, "Expected config file '#{expected}' to exist" unless expected.exist?
      end
      new(config_dir)
    end
    
    def session_secret
      @sessions['secret']
    end

  private

    def load_backend
      @backend = eval(File.read(@config_dir + "backend.rb"))
    end
    
    def load_encryption
      @encryption = YAML.load_file(@config_dir + "encryption.yml")
    end

    def load_sessions
      @sessions = YAML.load_file(@config_dir + "sessions.yml")
    end

    def load_api_keys
      @api_keys = YAML.load_file(@config_dir + "api_keys.yml")
    end

  end # InstanceConfiguration
end   # Kennedy
