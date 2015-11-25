module JOSE

  class JWT < Struct.new(:fields)

    # Decode API

    def self.from(object, modules = {})
      case object
      when JOSE::Map, Hash
        return from_map(object, modules)
      when String
        return from_binary(object, modules)
      when JOSE::JWT
        return object
      else
        raise ArgumentError, "'object' must be a Hash, String, or JOSE::JWT"
      end
    end

    def self.from_binary(object, modules = {})
      case object
      when String
        return from_map(JOSE.decode(object), modules)
      else
        raise ArgumentError, "'object' must be a String"
      end
    end

    def self.from_file(file, modules = {})
      return from_binary(File.binread(file), modules)
    end

    def self.from_map(object, modules = {})
      case object
      when JOSE::Map, Hash
        return from_fields(JOSE::JWT.new(JOSE::Map.new(object)), modules)
      else
        raise ArgumentError, "'object' must be a Hash"
      end
    end

    # Encode API

    def self.to_binary(jwt)
      return from(jwt).to_binary
    end

    def to_binary
      return JOSE.encode(to_map)
    end

    def self.to_file(jwt, file)
      return from(jwt).to_file(file)
    end

    def to_file(file)
      return File.binwrite(file, to_binary)
    end

    def self.to_map(jwt)
      return from(jwt).to_map
    end

    def to_map
      return fields
    end

    # API

    def self.decrypt(jwk, encrypted)
      decrypted, jwe = JOSE::JWK.block_decrypt(jwk, encrypted)
      return from_binary(decrypted), jwe
    end

    def self.encrypt(jwt, jwk, jwe = nil)
      return from(jwt).encrypt(jwk, jwe)
    end

    def encrypt(jwk, jwe = nil)
      plain_text = to_binary
      if jwe.nil?
        jwk = JOSE::JWK.from(jwk)
        jwe = jwk.kty.block_encryptor(jwk.fields, plain_text)
      end
      if jwe.is_a?(Hash)
        jwe = JOSE::Map.new(jwe)
      end
      if jwe.is_a?(JOSE::Map) and not jwe.has_key?('typ')
        jwe = jwe.put('typ', 'JWT')
      end
      return JOSE::JWK.block_encrypt(jwk, plain_text, jwe)
    end

    def self.peek_payload(signed)
      return JOSE::Map.new(JOSE.decode(JOSE::JWS.peek_payload(signed)))
    end

    def self.peek_protected(signed)
      return JOSE::JWS.peek_protected(signed)
    end

    def self.sign(jwt, jwk, jws = nil, header = nil)
      return from(jwt).sign(jwk, jws)
    end

    def sign(jwk, jws = nil, header = nil)
      plain_text = to_binary
      if jws.nil?
        jwk = JOSE::JWK.from(jwk)
        jws = jwk.kty.signer(jwk.fields, plain_text)
      end
      if jws.is_a?(Hash)
        jws = JOSE::Map.new(jws)
      end
      if jws.is_a?(JOSE::Map) and not jws.has_key?('typ')
        jws = jws.put('typ', 'JWT')
      end
      return JOSE::JWK.sign(jwk, plain_text, jws, header)
    end

    def self.verify(jwk, signed)
      verified, payload, jws = JOSE::JWK.verify(signed, jwk)
      jwt = from_binary(payload)
      return verified, jwt, jws
    end

    def self.verify_strict(jwk, allow, signed)
      verified, payload, jws = JOSE::JWK.verify(signed, allow, jwk)
      jwt = payload
      if verified
        jwt = from_binary(payload)
      end
      return verified, jwt, jws
    end

  private

    def self.from_fields(jwt, modules)
      return jwt
    end

  end
end

require 'jose/jws/alg'
