module JOSE::JWK::KTY

  def self.from_key(object)
    object = object.__getobj__ if object.is_a?(JOSE::JWK::PKeyProxy)
    case object
    when OpenSSL::PKey::EC
      return JOSE::JWK::KTY_EC.from_key(object)
    when OpenSSL::PKey::RSA
      return JOSE::JWK::KTY_RSA.from_key(object)
    else
      raise ArgumentError, "'object' is not a recognized key type: #{object.class.name}"
    end
  end

  def self.key_encryptor(kty, fields, key)
    if key.is_a?(String)
      return JOSE::Map[
        'alg' => 'PBES2-HS256+A128KW',
        'cty' => 'jwk+json',
        'enc' => 'A128GCM',
        'p2c' => 4096,
        'p2s' => JOSE.urlsafe_encode64(SecureRandom.random_bytes(16))
      ]
    else
      raise ArgumentError, "unhandled key type for key_encryptor"
    end
  end

end

require 'jose/jwk/pkey_proxy'

require 'jose/jwk/kty_ec'
require 'jose/jwk/kty_oct'
require 'jose/jwk/kty_okp_ed25519'
require 'jose/jwk/kty_okp_ed25519ph'
require 'jose/jwk/kty_okp_ed448'
require 'jose/jwk/kty_okp_ed448ph'
require 'jose/jwk/kty_okp_x25519'
require 'jose/jwk/kty_okp_x448'
require 'jose/jwk/kty_rsa'
