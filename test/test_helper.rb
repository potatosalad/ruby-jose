require 'pry'

if ENV['COVERAGE']
  require 'simplecov'
  SimpleCov.start
end

ENV['JOSE_CRYPTO_FALLBACK'] ||= '1'
$LOAD_PATH.unshift File.expand_path('../../lib', __FILE__)
require 'jose'

ENV['RANTLY_VERBOSE'] ||= '0'
require File.expand_path('../rantly_extensions', __FILE__)

require 'minitest/autorun'
if ENV['FOCUS']
  require 'minitest/focus'
end
