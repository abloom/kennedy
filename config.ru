require 'rubygems'
require 'sinatra'

require 'lib/kennedy/server'

Kennedy::Server.set :environment, :development
run Kennedy::Server