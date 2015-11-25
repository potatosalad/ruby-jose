module JOSE

  class SignedBinary < ::String
    def expand
      return JOSE::JWS.expand(self)
    end
  end

  class SignedMap < JOSE::Map
    def compact
      return JOSE::JWS.compact(self)
    end
  end

  class JWS < Struct.new(:alg, :b64, :fields)

    # Decode API

    def self.from(object, modules = {})
      case object
      when JOSE::Map, Hash
        return from_map(object, modules)
      when String
        return from_binary(object, modules)
      when JOSE::JWS
        return object
      else
        raise ArgumentError, "'object' must be a Hash, String, or JOSE::JWS"
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
        return from_fields(JOSE::JWS.new(nil, nil, JOSE::Map.new(object)), modules)
      else
        raise ArgumentError, "'object' must be a Hash"
      end
    end

    # Encode API

    def self.to_binary(jws)
      return from(jws).to_binary
    end

    def to_binary
      return JOSE.encode(to_map)
    end

    def self.to_file(jws, file)
      return from(jws).to_file(file)
    end

    def to_file(file)
      return File.binwrite(file, to_binary)
    end

    def self.to_map(jws)
      return from(jws).to_map
    end

    def to_map
      return alg.to_map(fields)
    end

    # API

    def self.compact(map)
      if map.is_a?(Hash) or map.is_a?(JOSE::Map)
        return JOSE::SignedBinary.new([
          map['protected'] || '',
          '.',
          map['payload'] || '',
          '.',
          map['signature'] || ''
        ].join)
      else
        raise ArgumentError, "'map' must be a Hash or a JOSE::Map"
      end
    end

    def self.expand(binary)
      if binary.is_a?(String)
        parts = binary.split('.')
        if parts.length == 3
          protected_binary, payload, signature = parts
          return JOSE::SignedMap[
            'payload'   => payload,
            'protected' => protected_binary,
            'signature' => signature
          ]
        else
          raise ArgumentError, "'binary' is not a valid signed String"
        end
      else
        raise ArgumentError, "'binary' must be a String"
      end
    end

    def self.peek_payload(signed)
      if signed.is_a?(String)
        signed = expand(signed)
      end
      return JOSE.urlsafe_decode64(signed['payload'])
    end

    def self.peek_protected(signed)
      if signed.is_a?(String)
        signed = expand(signed)
      end
      return JOSE::Map.new(JOSE.decode(JOSE.urlsafe_decode64(signed['protected'])))
    end

    def self.sign(key, plain_text, jws, header = nil)
      return from(jws).sign(key, plain_text, header)
    end

    def sign(key, plain_text, header = nil)
      protected_binary = JOSE.urlsafe_encode64(to_binary)
      payload = JOSE.urlsafe_encode64(plain_text)
      signing_input = signing_input(plain_text, protected_binary)
      signature = JOSE.urlsafe_encode64(alg.sign(key, signing_input))
      return signature_to_map(payload, protected_binary, header, key, signature)
    end

    # See https://tools.ietf.org/html/draft-ietf-jose-jws-signing-input-options-04
    def signing_input(payload, protected_binary = JOSE.urlsafe_encode64(to_binary))
      if b64 == true or b64.nil?
        payload = JOSE.urlsafe_encode64(payload)
      end
      return [protected_binary, '.', payload].join
    end

    def self.verify(key, signed)
      if signed.is_a?(String)
        signed = JOSE::JWS.expand(signed)
      end
      if signed.is_a?(Hash)
        signed = JOSE::SignedMap.new(signed)
      end
      if signed.is_a?(JOSE::Map) and signed['payload'].is_a?(String) and signed['protected'].is_a?(String) and signed['signature'].is_a?(String)
        jws = from_binary(JOSE.urlsafe_decode64(signed['protected']))
        signature = JOSE.urlsafe_decode64(signed['signature'])
        plain_text = JOSE.urlsafe_decode64(signed['payload'])
        return jws.verify(key, plain_text, signature, signed['protected'])
      else
        raise ArgumentError, "'signed' is not a valid signed String, Hash, or JOSE::Map"
      end
    end

    def verify(key, plain_text, signature, protected_binary = JOSE.urlsafe_encode64(to_binary))
      payload = JOSE.urlsafe_encode64(plain_text)
      signing_input = signing_input(plain_text, protected_binary)
      return alg.verify(key, signing_input, signature), plain_text, self
    end

    def self.verify_strict(key, allow, signed)
      if signed.is_a?(String)
        signed = JOSE::JWS.expand(signed)
      end
      if signed.is_a?(Hash)
        signed = JOSE::SignedMap.new(signed)
      end
      if signed.is_a?(JOSE::Map) and signed['payload'].is_a?(String) and signed['protected'].is_a?(String) and signed['signature'].is_a?(String)
        protected_map = JOSE.decode(JOSE.urlsafe_decode64(signed['protected']))
        plain_text = JOSE.urlsafe_decode64(signed['payload'])
        if allow.member?(protected_map['alg'])
          jws = from_map(protected_map)
          signature = JOSE.urlsafe_decode64(signed['signature'])
          return jws.verify(key, plain_text, signature, signed['protected'])
        else
          return false, plain_text, protected_map
        end
      else
        raise ArgumentError, "'signed' is not a valid signed String, Hash, or JOSE::Map"
      end
    end

  private

    def self.from_fields(jws, modules)
      if jws.fields.has_key?('b64')
        jws.b64 = jws.fields['b64']
        jws.fields = jws.fields.delete('b64')
        return from_fields(jws, modules)
      elsif jws.fields.has_key?('alg') and jws.fields['alg'].is_a?(String)
        alg = modules[:alg] || case
        when jws.fields['alg'].start_with?('ES')
          JOSE::JWS::ALG_ECDSA
        when jws.fields['alg'].start_with?('HS')
          JOSE::JWS::ALG_HMAC
        when jws.fields['alg'].start_with?('PS')
          JOSE::JWS::ALG_RSA_PSS
        when jws.fields['alg'].start_with?('RS')
          JOSE::JWS::ALG_RSA_PKCS1_V1_5
        when jws.fields['alg'] == 'none'
          JOSE::JWS::ALG_none
        else
          raise ArgumentError, "unknown 'alg': #{jws.fields['alg'].inspect}"
        end
        jws.alg, jws.fields = alg.from_map(jws.fields)
        return from_fields(jws, modules)
      elsif jws.alg.nil?
        raise ArgumentError, "missing required keys: 'alg'"
      else
        return jws
      end
    end

    def signature_to_map(payload, protected_binary, header, key, signature)
      if header and header.is_a?(Hash)
        header = JOSE::Map.new(header)
      end
      header ||= JOSE::Map[]
      if key.is_a?(JOSE::JWK) and key.fields['kid'].is_a?(String)
        header = header.put('kid', key.fields['kid'])
      end
      if header.size == 0
        return JOSE::SignedMap['payload' => payload, 'protected' => protected_binary, 'signature' => signature]
      else
        return JOSE::SignedMap['header' => header.to_hash, 'payload' => payload, 'protected' => protected_binary, 'signature' => signature]
      end
    end

  end
end

require 'jose/jws/alg'
