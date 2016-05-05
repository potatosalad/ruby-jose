require 'jose/version'

require 'base64'
require 'hamster/hash'
require 'json'
require 'openssl'
require 'thread'

module JOSE
  class Map < Hamster::Hash; end
end

module JOSE

  extend self

  MUTEX = Mutex.new

  @__crypto_fallback__ = ENV['JOSE_CRYPTO_FALLBACK'] ? true : false
  @__unsecured_signing__ = ENV['JOSE_UNSECURED_SIGNING'] ? true : false

  def __crypto_fallback__
    return @__crypto_fallback__
  end

  def __crypto_fallback__=(boolean)
    boolean = !!boolean
    MUTEX.synchronize {
      @__crypto_fallback__ = boolean
      __config_change__
    }
  end

  def __curve25519_module__
    return JOSE::JWA::Curve25519.__implementation__
  end

  def __curve25519_module__=(m)
    JOSE::JWA::Curve25519.__implementation__ = m
  end

  def __curve448_module__
    return JOSE::JWA::Curve448.__implementation__
  end

  def __curve448_module__=(m)
    JOSE::JWA::Curve448.__implementation__ = m
  end

  def decode(binary)
    return JSON.load(binary)
  end

  def encode(term)
    return JSON.dump(sort_maps(term))
  end

  def __unsecured_signing__
    return @__unsecured_signing__
  end

  def __unsecured_signing__=(boolean)
    boolean = !!boolean
    MUTEX.synchronize {
      @__unsecured_signing__ = boolean
      __config_change__
    }
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

  def __config_change__
    JOSE::JWA::Curve25519.__config_change__
    JOSE::JWA::Curve448.__config_change__
  end

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

require 'jose/jwa'
require 'jose/jwe'
require 'jose/jwk'
require 'jose/jws'
require 'jose/jwt'
