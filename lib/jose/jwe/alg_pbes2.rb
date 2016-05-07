class JOSE::JWE::ALG_PBES2 < Struct.new(:hmac, :bits, :salt, :iter)

  # JOSE::JWE callbacks

  def self.from_map(fields)
    bits = nil
    hmac = nil
    case fields['alg']
    when 'PBES2-HS256+A128KW'
      bits = 128
      hmac = OpenSSL::Digest::SHA256
    when 'PBES2-HS384+A192KW'
      bits = 192
      hmac = OpenSSL::Digest::SHA384
    when 'PBES2-HS512+A256KW'
      bits = 256
      hmac = OpenSSL::Digest::SHA512
    else
      raise ArgumentError, "invalid 'alg' for JWE: #{fields['alg'].inspect}"
    end
    iter = nil
    if not fields.has_key?('p2c')
      iter = bits * 32
    elsif fields['p2c'].is_a?(Integer) and fields['p2c'] >= 0
      iter = fields['p2c']
    else
      raise ArgumentError, "invalid 'p2c' for JWE: #{fields['p2c'].inspect}"
    end
    salt = nil
    if not fields.has_key?('p2s')
      salt = nil
    elsif fields['p2s'].is_a?(String)
      salt = wrap_salt(fields['alg'], JOSE.urlsafe_decode64(fields['p2s']))
    else
      raise ArgumentError, "invalid 'p2s' for JWE: #{fields['p2s'].inspect}"
    end
    return new(hmac, bits, salt, iter), fields.except('alg', 'p2c', 'p2s')
  end

  def to_map(fields)
    alg = algorithm
    p2c = iter
    if salt.nil?
      return fields.put('alg', alg).put('p2c', p2c)
    else
      p2s = JOSE.urlsafe_encode64(unwrap_salt(salt))
      return fields.put('alg', alg).put('p2c', p2c).put('p2s', p2s)
    end
  end

  # JOSE::JWE::ALG callbacks

  def generate_key(fields, enc)
    alg = algorithm
    extra_fields = {
      'p2c' => iter
    }
    if not salt.nil?
      extra_fields['p2s'] = JOSE.urlsafe_encode64(unwrap_salt(salt))
    end
    return JOSE::JWE::ALG.generate_key([:oct, 16], alg, enc.algorithm).merge(extra_fields)
  end

  def key_decrypt(key, enc, encrypted_key)
    if key.is_a?(JOSE::JWK)
      key = key.kty.derive_key
    end
    derived_key = OpenSSL::PKCS5.pbkdf2_hmac(key, salt, iter, bits.div(8) + (bits % 8), hmac.new)
    decrypted_key = JOSE::JWA::AES_KW.unwrap(encrypted_key, derived_key)
    return decrypted_key
  end

  def key_encrypt(key, enc, decrypted_key)
    if key.is_a?(JOSE::JWK)
      key = key.kty.derive_key
    end
    new_alg = self
    if new_alg.salt.nil?
      new_alg = JOSE::JWE::ALG_PBES2.new(hmac, bits, wrap_salt(SecureRandom.random_bytes(bits.div(8))), iter)
    end
    derived_key = OpenSSL::PKCS5.pbkdf2_hmac(key, new_alg.salt, new_alg.iter, new_alg.bits.div(8) + (new_alg.bits % 8), new_alg.hmac.new)
    encrypted_key = JOSE::JWA::AES_KW.wrap(decrypted_key, derived_key)
    return encrypted_key, new_alg
  end

  def next_cek(key, enc)
    return enc.next_cek, self
  end

  # API functions

  def algorithm
    if hmac == OpenSSL::Digest::SHA256
      'PBES2-HS256+A128KW'
    elsif hmac == OpenSSL::Digest::SHA384
      'PBES2-HS384+A192KW'
    elsif hmac == OpenSSL::Digest::SHA512
      'PBES2-HS512+A256KW'
    else
      raise ArgumentError, "unhandled JOSE::JWE::ALG_PBES2 hmac: #{hmac.inspect}"
    end
  end

  def self.unwrap_salt(algorithm, salt)
    salt_s = StringIO.new(salt)
    if salt_s.read(algorithm.length) != algorithm or salt_s.getbyte != 0
      raise ArgumentError, "unrecognized salt value"
    else
      return salt_s.read
    end
  end

  def unwrap_salt(salt)
    return JOSE::JWE::ALG_PBES2.unwrap_salt(algorithm, salt)
  end

  def self.wrap_salt(algorithm, salt_input)
    return [algorithm, 0x00, salt_input].pack('a*Ca*')
  end

  def wrap_salt(salt_input)
    return JOSE::JWE::ALG_PBES2.wrap_salt(algorithm, salt_input)
  end

end
