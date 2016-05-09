if ENV['COVERAGE']
  require 'simplecov'
  SimpleCov.start
end

ENV['RANTLY_VERBOSE'] ||= '0'

require 'securerandom'
require 'rantly/minitest_extensions'

class Rantly
  def urlsafe_base64_dict(n = self.size)
    return dict(range(0, n)) {
      [
        SecureRandom.urlsafe_base64(range(0, n)),
        SecureRandom.urlsafe_base64(range(0, n))
      ]
    }
  end
end

$LOAD_PATH.unshift File.expand_path('../../lib', __FILE__)
require 'jose'

require 'minitest/autorun'
