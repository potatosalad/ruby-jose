class JOSE::JWE::ALG_AES_KW < Struct.new(:bits)

  # JOSE::JWE callbacks

  def self.from_map(fields)
    bits = case fields['alg']
    when 'A128KW'
      128
    when 'A192KW'
      192
    when 'A256KW'
      256
    else
      raise ArgumentError, "invalid 'alg' for JWE: #{fields['alg'].inspect}"
    end
    return new(bits), fields.except('alg')
  end

  def to_map(fields)
    alg = case bits
    when 128
      'A128KW'
    when 192
      'A192KW'
    when 256
      'A256KW'
    else
      raise ArgumentError, "unhandled JOSE::JWE::ALG_AES_KW bits: #{bits.inspect}"
    end
    return fields.put('alg', alg)
  end

  # JOSE::JWE::ALG callbacks

  def key_decrypt(key, enc, encrypted_key)
    if key.is_a?(JOSE::JWK)
      key = key.kty.derive_key
    end
    derived_key = key
    decrypted_key = JOSE::JWA::AES_KW.unwrap(encrypted_key, derived_key)
    return decrypted_key
  end

  def key_encrypt(key, enc, decrypted_key)
    if key.is_a?(JOSE::JWK)
      key = key.kty.derive_key
    end
    derived_key = key
    encrypted_key = JOSE::JWA::AES_KW.wrap(decrypted_key, derived_key)
    return encrypted_key, self
  end

  def next_cek(key, enc)
    return enc.next_cek
  end

end
