require 'jose/version'

require 'base64'
require 'hamster/hash'
require 'json'
require 'openssl'

module JOSE
  class Map < Hamster::Hash; end
end

require 'jose/jwa'
require 'jose/jwe'
require 'jose/jwk'
require 'jose/jws'
require 'jose/jwt'

module JOSE

  extend self

  def decode(binary)
    return JSON.load(binary)
  end

  def encode(term)
    return JSON.dump(sort_maps(term))
  end

  def urlsafe_decode64(binary)
    case binary.bytesize % 4
    when 2
      binary += '=='
    when 3
      binary += '='
    end
    return Base64.urlsafe_decode64(binary)
  end

  def urlsafe_encode64(binary)
    return Base64.urlsafe_encode64(binary).tr('=', '')
  end

private

  def sort_maps(term)
    case term
    when Hash, JOSE::Map
      return term.keys.sort.each_with_object(Hash.new) do |key, hash|
        hash[key] = sort_maps(term[key])
      end
    when Array
      return term.map do |item|
        sort_maps(item)
      end
    else
      return term
    end
  end

end
