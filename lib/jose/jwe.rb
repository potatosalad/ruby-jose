module JOSE

  class EncryptedBinary < ::String
    def expand
      return JOSE::JWE.expand(self)
    end
  end

  class EncryptedMap < JOSE::Map
    def compact
      return JOSE::JWE.compact(self)
    end
  end

  class JWE < Struct.new(:alg, :enc, :zip, :fields)

    # Decode API

    def self.from(object, modules = {})
      case object
      when JOSE::Map, Hash
        return from_map(object, modules)
      when String
        return from_binary(object, modules)
      when JOSE::JWE
        return object
      else
        raise ArgumentError, "'object' must be a Hash, String, or JOSE::JWE"
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
        return from_fields(JOSE::JWE.new(nil, nil, nil, JOSE::Map.new(object)), modules)
      else
        raise ArgumentError, "'object' must be a Hash"
      end
    end

    # Encode API

    def self.to_binary(jwe)
      return from(jwe).to_binary
    end

    def to_binary
      return JOSE.encode(to_map)
    end

    def self.to_file(jwe, file)
      return from(jwe).to_file(file)
    end

    def to_file(file)
      return File.binwrite(file, to_binary)
    end

    def self.to_map(jwe)
      return from(jwe).to_map
    end

    def to_map
      if zip.nil?
        return alg.to_map(enc.to_map(fields))
      else
        return alg.to_map(enc.to_map(zip.to_map(fields)))
      end
    end

    # API

    def self.block_decrypt(key, encrypted)
      if encrypted.is_a?(String)
        encrypted = JOSE::JWE.expand(encrypted)
      end
      if encrypted.is_a?(Hash)
        encrypted = JOSE::EncryptedMap.new(encrypted)
      end
      if encrypted.is_a?(JOSE::Map) and encrypted['ciphertext'].is_a?(String) and encrypted['encrypted_key'].is_a?(String) and encrypted['iv'].is_a?(String) and encrypted['protected'].is_a?(String) and encrypted['tag'].is_a?(String)
        jwe = from_binary(JOSE.urlsafe_decode64(encrypted['protected']))
        encrypted_key = JOSE.urlsafe_decode64(encrypted['encrypted_key'])
        iv = JOSE.urlsafe_decode64(encrypted['iv'])
        cipher_text = JOSE.urlsafe_decode64(encrypted['ciphertext'])
        cipher_tag = JOSE.urlsafe_decode64(encrypted['tag'])
        if encrypted['aad'].is_a?(String)
          concat_aad = [encrypted['protected'], '.', encrypted['aad']].join
          return jwe.block_decrypt(key, concat_aad, cipher_text, cipher_tag, encrypted_key, iv), jwe
        else
          return jwe.block_decrypt(key, encrypted['protected'], cipher_text, cipher_tag, encrypted_key, iv), jwe
        end
      else
        raise ArgumentError, "'encrypted' is not a valid encrypted String, Hash, or JOSE::Map"
      end
    end

    def block_decrypt(key, aad, cipher_text, cipher_tag, encrypted_key, iv)
      cek = key_decrypt(key, encrypted_key)
      return uncompress(enc.block_decrypt([aad, cipher_text, cipher_tag], cek, iv))
    end

    def self.block_encrypt(key, block, jwe, cek = nil, iv = nil)
      return from(jwe).block_encrypt(key, block, cek, iv)
    end

    def block_encrypt(key, block, cek = nil, iv = nil)
      cek ||= next_cek(key)
      iv ||= next_iv
      aad, plain_text = block
      if plain_text.nil?
        plain_text = aad
        aad = nil
      end
      encrypted_key, jwe = key_encrypt(key, cek)
      protected_binary = JOSE.urlsafe_encode64(jwe.to_binary)
      if aad.nil?
        cipher_text, cipher_tag = enc.block_encrypt([protected_binary, jwe.compress(plain_text)], cek, iv)
        return JOSE::EncryptedMap[
          'ciphertext'    => JOSE.urlsafe_encode64(cipher_text),
          'encrypted_key' => JOSE.urlsafe_encode64(encrypted_key),
          'iv'            => JOSE.urlsafe_encode64(iv),
          'protected'     => protected_binary,
          'tag'           => JOSE.urlsafe_encode64(cipher_tag)
        ]
      else
        aad_b64 = JOSE.urlsafe_encode64(aad)
        concat_aad = [protected_binary, '.', aad_b64].join
        cipher_text, cipher_tag = enc.block_encrypt([aad_b64, jwe.compress(plain_text)], cek, iv)
        return JOSE::EncryptedMap[
          'aad'           => aad_b64,
          'ciphertext'    => JOSE.urlsafe_encode64(cipher_text),
          'encrypted_key' => JOSE.urlsafe_encode64(encrypted_key),
          'iv'            => JOSE.urlsafe_encode64(iv),
          'protected'     => protected_binary,
          'tag'           => JOSE.urlsafe_encode64(cipher_tag)
        ]
      end
    end

    def self.compact(map)
      if map.is_a?(Hash) or map.is_a?(JOSE::Map)
        if map.has_key?('aad')
          raise ArgumentError, "'map' with 'aad' cannot be compacted"
        end
        return JOSE::EncryptedBinary.new([
          map['protected'] || '',
          '.',
          map['encrypted_key'] || '',
          '.',
          map['iv'] || '',
          '.',
          map['ciphertext'] || '',
          '.',
          map['tag'] || ''
        ].join)
      else
        raise ArgumentError, "'map' must be a Hash or a JOSE::Map"
      end
    end

    def compress(plain_text)
      if zip.nil?
        return plain_text
      else
        return zip.compress(plain_text)
      end
    end

    def self.expand(binary)
      if binary.is_a?(String)
        parts = binary.split('.')
        if parts.length == 5
          protected_binary, encrypted_key, initialization_vector, cipher_text, authentication_tag = parts
          return JOSE::EncryptedMap[
            'ciphertext'    => cipher_text,
            'encrypted_key' => encrypted_key,
            'iv'            => initialization_vector,
            'protected'     => protected_binary,
            'tag'           => authentication_tag
          ]
        else
          raise ArgumentError, "'binary' is not a valid encrypted String"
        end
      else
        raise ArgumentError, "'binary' must be a String"
      end
    end

    def key_decrypt(key, encrypted_key)
      return alg.key_decrypt(key, enc, encrypted_key)
    end

    def key_encrypt(key, decrypted_key)
      encrypted_key, new_alg = alg.key_encrypt(key, enc, decrypted_key)
      new_jwe = JOSE::JWE.from_map(to_map)
      new_jwe.alg = new_alg
      return encrypted_key, new_jwe
    end

    def next_cek(key)
      return alg.next_cek(key, enc)
    end

    def next_iv
      return enc.next_iv
    end

    def self.peek_protected(encrypted)
      if encrypted.is_a?(String)
        encrypted = expand(encrypted)
      end
      return JOSE::Map.new(JOSE.decode(JOSE.urlsafe_decode64(encrypted['protected'])))
    end

    def uncompress(cipher_text)
      if zip.nil?
        return cipher_text
      else
        return zip.uncompress(cipher_text)
      end
    end

  private

    def self.from_fields(jwe, modules)
      if jwe.fields.has_key?('alg')
        alg = modules[:alg] || case jwe.fields['alg']
        when 'A128KW', 'A192KW', 'A256KW'
          JOSE::JWE::ALG_AES_KW
        when 'A128GCMKW', 'A192GCMKW', 'A256GCMKW'
          JOSE::JWE::ALG_AES_GCM_KW
        when 'dir'
          JOSE::JWE::ALG_dir
        when 'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW'
          JOSE::JWE::ALG_ECDH_ES
        when 'PBES2-HS256+A128KW', 'PBES2-HS384+A192KW', 'PBES2-HS512+A256KW'
          JOSE::JWE::ALG_PBES2
        when 'RSA1_5', 'RSA-OAEP', 'RSA-OAEP-256'
          JOSE::JWE::ALG_RSA
        else
          raise ArgumentError, "unknown 'alg': #{jwe.fields['alg'].inspect}"
        end
        jwe.alg, jwe.fields = alg.from_map(jwe.fields)
        return from_fields(jwe, modules)
      elsif jwe.fields.has_key?('enc')
        enc = modules[:enc] || case jwe.fields['enc']
        when 'A128CBC-HS256', 'A192CBC-HS384', 'A256CBC-HS512'
          JOSE::JWE::ENC_AES_CBC_HMAC
        when 'A128GCM', 'A192GCM', 'A256GCM'
          JOSE::JWE::ENC_AES_GCM
        else
          raise ArgumentError, "unknown 'enc': #{jwe.fields['enc'].inspect}"
        end
        jwe.enc, jwe.fields = enc.from_map(jwe.fields)
        return from_fields(jwe, modules)
      elsif jwe.fields.has_key?('zip')
        zip = modules[:zip] || case jwe.fields['zip']
        when 'DEF'
          JOSE::JWE::ZIP_DEF
        else
          raise ArgumentError, "unknown 'zip': #{jwe.fields['zip'].inspect}"
        end
        jwe.zip, jwe.fields = zip.from_map(jwe.fields)
        return from_fields(jwe, modules)
      elsif jwe.alg.nil? and jwe.enc.nil?
        raise ArgumentError, "missing required keys: 'alg' and 'enc'"
      else
        return jwe
      end
    end

  end
end

require 'jose/jwe/alg'
require 'jose/jwe/enc'
require 'jose/jwe/zip'
