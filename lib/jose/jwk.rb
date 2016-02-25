module JOSE
  class JWK < Struct.new(:keys, :kty, :fields)

    # Decode API

    def self.from(object, modules = nil, key = nil)
      case object
      when JOSE::Map, Hash
        return from_map(object, modules, key)
      when String
        return from_binary(object, modules, key)
      when JOSE::JWK
        return object
      else
        raise ArgumentError, "'object' must be a Hash, String, or JOSE::JWK"
      end
    end

    def self.from_binary(object, modules = nil, key = nil)
      if (modules.is_a?(String) or modules.is_a?(JOSE::JWK)) and key.nil?
        key = modules
        modules = {}
      end
      modules ||= {}
      case object
      when String
        if key
          plain_text, jwe = JOSE::JWE.block_decrypt(key, object)
          return from_binary(plain_text, modules), jwe
        else
          return from_map(JOSE.decode(object), modules)
        end
      else
        raise ArgumentError, "'object' must be a String"
      end
    end

    def self.from_file(file, modules = nil, key = nil)
      return from_binary(File.binread(file), modules, key)
    end

    def self.from_key(object, modules = {})
      kty = modules[:kty] || JOSE::JWK::KTY
      return JOSE::JWK.new(nil, *kty.from_key(object))
    end

    def self.from_map(object, modules = nil, key = nil)
      if (modules.is_a?(String) or modules.is_a?(JOSE::JWK)) and key.nil?
        key = modules
        modules = {}
      end
      modules ||= {}
      case object
      when JOSE::Map, Hash
        if key
          plain_text, jwe = JOSE::JWE.block_decrypt(key, object)
          return from_binary(plain_text, modules), jwe
        else
          return from_fields(JOSE::JWK.new(nil, nil, JOSE::Map.new(object)), modules)
        end
      else
        raise ArgumentError, "'object' must be a String"
      end
    end

    def self.from_pem(object, modules = nil, password = nil)
      if modules.is_a?(String) and password.nil?
        password = modules
        modules  = {}
      end
      modules ||= {}
      kty = modules[:kty] || JOSE::JWK::PEM
      return JOSE::JWK.new(nil, *kty.from_binary(object, password))
    end

    def self.from_pem_file(file, modules = nil, password = nil)
      return from_pem(File.binread(file), modules, password)
    end

    def self.from_oct(object, modules = {})
      kty = modules[:kty] || JOSE::JWK::KTY_oct
      return JOSE::JWK.new(nil, *kty.from_oct(object))
    end

    def self.from_oct_file(file, modules = {})
      return from_oct(File.binread(file), modules)
    end

    def self.from_okp(object, modules = {})
      raise ArgumentError, "object must be an Array of length 2" if not object.is_a?(Array) or object.length != 2
      kty = modules[:kty] || case object[0]
      when :Ed25519
        JOSE::JWK::KTY_OKP_Ed25519
      when :Ed25519ph
        JOSE::JWK::KTY_OKP_Ed25519ph
      when :Ed448
        JOSE::JWK::KTY_OKP_Ed448
      when :Ed448ph
        JOSE::JWK::KTY_OKP_Ed448ph
      when :X25519
        JOSE::JWK::KTY_OKP_X25519
      when :X448
        JOSE::JWK::KTY_OKP_X448
      else
        raise ArgumentError, "unrecognized :okp object"
      end
      return JOSE::JWK.new(nil, *kty.from_okp(object))
    end

    # Encode API

    def self.to_binary(jwk, key = nil, jwe = nil)
      return from(jwk).to_binary(key, jwe)
    end

    def to_binary(key = nil, jwe = nil)
      if not key.nil?
        jwe ||= kty.key_encryptor(fields, key)
      end
      if key and jwe
        return to_map(key, jwe).compact
      else
        return JOSE.encode(to_map)
      end
    end

    def self.to_file(jwk, file, key = nil, jwe = nil)
      return from(jwk).to_file(file, key, jwe)
    end

    def to_file(file, key = nil, jwe = nil)
      return File.binwrite(file, to_binary(key, jwe))
    end

    def self.to_key(jwk)
      return from(jwk).to_key
    end

    def to_key
      return kty.to_key
    end

    def self.to_map(jwk, key = nil, jwe = nil)
      return from(jwk).to_map(key, jwe)
    end

    def to_map(key = nil, jwe = nil)
      if not key.nil?
        jwe ||= kty.key_encryptor(fields, key)
      end
      if key and jwe
        return JOSE::JWE.block_encrypt(key, to_binary, jwe)
      else
        return kty.to_map(fields)
      end
    end

    def self.to_oct(jwk)
      return from(jwk).to_oct
    end

    def to_oct
      return kty.to_oct
    end

    def self.to_okp(jwk)
      return from(jwk).to_okp
    end

    def to_okp
      return kty.to_okp
    end

    def self.to_pem(jwk, password = nil)
      return from(jwk).to_pem(password)
    end

    def to_pem(password = nil)
      return kty.to_pem(password)
    end

    def self.to_public(jwk)
      return from(jwk).to_public
    end

    def to_public
      return JOSE::JWK.from_map(to_public_map)
    end

    def self.to_public_key(jwk)
      return from(jwk).to_public_key
    end

    def to_public_key
      return to_public.to_key
    end

    def self.to_public_map(jwk)
      return from(jwk).to_public_map
    end

    def to_public_map
      return kty.to_public_map(fields)
    end

    def self.to_thumbprint_map(jwk)
      return from(jwk).to_thumbprint_map
    end

    def to_thumbprint_map
      return kty.to_thumbprint_map(fields)
    end

    # API

    def self.block_decrypt(jwk, encrypted)
      return from(jwk).block_decrypt(encrypted)
    end

    def block_decrypt(encrypted)
      return JOSE::JWE.block_decrypt(self, encrypted)
    end

    def self.block_encrypt(jwk, plain_text, jwe = nil)
      return from(jwk).block_encrypt(plain_text, jwe)
    end

    def block_encrypt(plain_text, jwe = nil)
      jwe ||= kty.block_encryptor(fields, plain_text)
      return JOSE::JWE.block_encrypt(self, plain_text, jwe)
    end

    def self.box_decrypt(jwk, encrypted)
      return from(jwk).box_decrypt(encrypted)
    end

    def box_decrypt(encrypted)
      return JOSE::JWE.block_decrypt(self, encrypted)
    end

    # Generates an ephemeral private key based on other public key curve.
    def box_encrypt(plain_text, my_private_jwk = nil, jwe = nil)
      generated_jwk = nil
      other_public_jwk = self
      if my_private_jwk.nil?
        generated_jwk = my_private_jwk = other_public_jwk.generate_key
      end
      if not my_private_jwk.is_a?(JOSE::JWK)
        my_private_jwk = JOSE::JWK.from(my_private_jwk)
      end
      if jwe.nil?
        jwe = other_public_jwk.kty.block_encryptor(fields, plain_text)
      end
      if jwe.is_a?(Hash)
        jwe = JOSE::Map.new(jwe)
      end
      if jwe.is_a?(JOSE::Map)
        if jwe['apu'].nil?
          jwe = jwe.put('apu', my_private_jwk.fields['kid'] || my_private_jwk.thumbprint)
        end
        if jwe['apv'].nil?
          jwe = jwe.put('apv', other_public_jwk.fields['kid'] || other_public_jwk.thumbprint)
        end
        if jwe['epk'].nil?
          jwe = jwe.put('epk', my_private_jwk.to_public_map)
        end
      end
      if generated_jwk
        return JOSE::JWE.block_encrypt([other_public_jwk, my_private_jwk], plain_text, jwe), generated_jwk
      else
        return JOSE::JWE.block_encrypt([other_public_jwk, my_private_jwk], plain_text, jwe)
      end
    end

    def derive_key(*args)
      return kty.derive_key(*args)
    end

    def self.generate_key(params)
      if params.is_a?(Array) and (params.length == 2 or params.length == 3)
        case params[0]
        when :ec
          return JOSE::JWK.new(nil, *JOSE::JWK::KTY_EC.generate_key(params))
        when :oct
          return JOSE::JWK.new(nil, *JOSE::JWK::KTY_oct.generate_key(params))
        when :okp
          case params[1]
          when :Ed25519
            return JOSE::JWK.new(nil, *JOSE::JWK::KTY_OKP_Ed25519.generate_key(params))
          when :Ed25519ph
            return JOSE::JWK.new(nil, *JOSE::JWK::KTY_OKP_Ed25519ph.generate_key(params))
          when :Ed448
            return JOSE::JWK.new(nil, *JOSE::JWK::KTY_OKP_Ed448.generate_key(params))
          when :Ed448ph
            return JOSE::JWK.new(nil, *JOSE::JWK::KTY_OKP_Ed448ph.generate_key(params))
          when :X25519
            return JOSE::JWK.new(nil, *JOSE::JWK::KTY_OKP_X25519.generate_key(params))
          when :X448
            return JOSE::JWK.new(nil, *JOSE::JWK::KTY_OKP_X448.generate_key(params))
          else
            raise ArgumentError, "invalid :okp key generation params"
          end
        when :rsa
          return JOSE::JWK.new(nil, *JOSE::JWK::KTY_RSA.generate_key(params))
        else
          raise ArgumentError, "invalid key generation params"
        end
      elsif params.is_a?(JOSE::JWK)
        return params.generate_key
      elsif params.respond_to?(:generate_key)
        return JOSE::JWK.new(nil, *params.generate_key(JOSE::Map[]))
      else
        raise ArgumentError, "invalid key generation params"
      end
    end

    def generate_key
      return JOSE::JWK.new(nil, *kty.generate_key(fields))
    end

    def self.shared_secret(your_jwk, my_jwk)
      return from(your_jwk).shared_secret(from(my_jwk))
    end

    def shared_secret(other_jwk)
      other_jwk = from(other_jwk) if not other_jwk.is_a?(JOSE::JWK)
      raise ArgumentError, "key types must match" if other_jwk.kty.class != kty.class
      raise ArgumentError, "key type does not support shared secret computations" if not kty.respond_to?(:derive_key)
      return kty.derive_key(other_jwk)
    end

    def self.sign(jwk, plain_text, jws = nil, header = nil)
      return from(jwk).sign(plain_text, jws, header)
    end

    def sign(plain_text, jws = nil, header = nil)
      jws ||= kty.signer(fields, plain_text)
      return JOSE::JWS.sign(self, plain_text, jws, header)
    end

    def self.verify(signed, jwk)
      return from(jwk).verify(signed)
    end

    def verify(signed)
      return JOSE::JWS.verify(self, signed)
    end

    def self.verify_strict(signed, allow, jwk)
      return from(jwk).verify_strict(signed, allow)
    end

    def verify_strict(signed, allow)
      return JOSE::JWS.verify_strict(self, allow, signed)
    end

    # See https://tools.ietf.org/html/rfc7638
    def self.thumbprint(digest_type, jwk = nil)
      if jwk.nil?
        jwk = digest_type
        digest_type = nil
      end
      return from(jwk).thumbprint(digest_type)
    end

    def thumbprint(digest_type = nil)
      digest_type ||= 'SHA256'
      thumbprint_binary = JOSE.encode(to_thumbprint_map)
      return JOSE.urlsafe_encode64(OpenSSL::Digest.new(digest_type).digest(thumbprint_binary))
    end

  private

    def self.from_fields(jwk, modules)
      if jwk.fields.has_key?('keys')
        keys = modules[:keys] || JOSE::JWK::Set
        jwk.keys, jwk.fields = keys.from_map(jwk.fields)
        return from_fields(jwk, modules)
      elsif jwk.fields.has_key?('kty')
        kty = modules[:kty] || case jwk.fields['kty']
        when 'EC'
          JOSE::JWK::KTY_EC
        when 'oct'
          JOSE::JWK::KTY_oct
        when 'OKP'
          case jwk.fields['crv']
          when 'Ed25519'
            JOSE::JWK::KTY_OKP_Ed25519
          when 'Ed25519ph'
            JOSE::JWK::KTY_OKP_Ed25519ph
          when 'Ed448'
            JOSE::JWK::KTY_OKP_Ed448
          when 'Ed448ph'
            JOSE::JWK::KTY_OKP_Ed448ph
          when 'X25519'
            JOSE::JWK::KTY_OKP_X25519
          when 'X448'
            JOSE::JWK::KTY_OKP_X448
          else
            raise ArgumentError, "unknown 'crv' for 'kty' of 'OKP': #{jwk.fields['crv'].inspect}"
          end
        when 'RSA'
          JOSE::JWK::KTY_RSA
        else
          raise ArgumentError, "unknown 'kty': #{jwk.fields['kty'].inspect}"
        end
        jwk.kty, jwk.fields = kty.from_map(jwk.fields)
        return from_fields(jwk, modules)
      elsif jwk.keys.nil? and jwk.kty.nil?
        raise ArgumentError, "missing required keys: 'keys' or 'kty'"
      else
        return jwk
      end
    end

  end
end

require 'jose/jwk/pem'
require 'jose/jwk/set'
require 'jose/jwk/kty'
