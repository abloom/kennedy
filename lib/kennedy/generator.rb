require 'pathname'
require 'erb'
require 'fileutils'
require 'digest/sha1'

module Kennedy
  class Generator
    TemplateDir = (Pathname(__FILE__).parent.parent.parent + "template").expand_path
    TemplateType = ".erb"

    def run(arguments)
      @app_name = arguments.first
      raise ArgumentError, "An app name must be given" if @app_name.nil? || @app_name.empty?
      create_destination_directory
      copy_files
    end
  
  private
    
    def create_destination_directory
      @dest = Pathname(@app_name)
      log_create(@dest)
      @dest.mkpath
    end

    def copy_files
      Pathname.glob("#{template_dir}/**/*").each do |pn|
        next if pn.directory?
        relative = pn.relative_path_from(TemplateDir)
        dest_path = @dest + relative
        unless dest_path.dirname.exist?
          log_create(dest_path.dirname)
          dest_path.dirname.mkpath
        end
        is_template?(pn) ? evaluate_and_write_template(pn, dest_path) : copy_file(pn, dest_path)
      end
    end
    
    def is_template?(path)
      Pathname(path).extname == template_type
    end
    
    def evaluate_and_write_template(path, dest)
      dest = dest.sub(/#{Regexp.escape(dest.extname)}$/, "")
      log_create(dest)
      dest.open('w') do |f|
        f << ERB.new(path.read).result(binding)
      end
    end
    
    def copy_file(path, dest)
      log_create(dest)
      FileUtils.cp_r(path.expand_path.to_s, dest.expand_path.to_s)
    end

    def template_type
      TemplateType
    end

    def template_dir
      TemplateDir
    end

    def log_create(path)
      puts "Creating '#{path}'"
    end

  end
end
