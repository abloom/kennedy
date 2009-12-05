require 'rubygems'
require 'rake'

begin
  require 'jeweler'
  Jeweler::Tasks.new do |gem|
    gem.name = "kennedy"
    gem.summary = %Q{A simple single-sign-on client and server library.}
    gem.description = %Q{Kennedy is out for Castronaut. A simple single-sign-on client and server library.}
    gem.email = "gabriel.gironda@gmail.com"
    gem.homepage = "http://github.com/gabrielg/kennedy"
    gem.authors = ["gabrielg"]
    gem.add_development_dependency "riot", ">= 0"
    gem.add_development_dependency "maruku"
    gem.add_development_dependency "yard"
    gem.add_dependency "ruby-net-ldap"
    gem.add_dependency "json"
    gem.add_dependency "sinatra"
    gem.add_dependency "rack"
  end
  Jeweler::GemcutterTasks.new
rescue LoadError
  puts "Jeweler (or a dependency) not available. Install it with: gem install jeweler"
end

require 'rake/testtask'
Rake::TestTask.new(:test) do |test|
  test.libs << 'lib' << 'test'
  test.pattern = 'test/**/*_test.rb'
  test.verbose = true
end

task :test => :check_dependencies

task :default => :test

task :generate_main_rdoc do
  require 'maruku'
  content = File.read('README.markdown')
  doc = Maruku.new(content)
  File.open(File.join(File.dirname(__FILE__), 'MAIN.rdoc'), 'w') { |f| f << doc.to_html } 
end

begin
  require 'yard'
  YARD::Rake::YardocTask.new(:yard => :generate_main_rdoc)
rescue LoadError
  task :yardoc do
    abort "YARD is not available. In order to run yardoc, you must: sudo gem install yard"
  end
end
