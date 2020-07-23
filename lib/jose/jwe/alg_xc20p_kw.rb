class JOSE::JWE::ALG_XC20P_KW < Struct.new(:cipher_name, :bits, :iv, :tag)

  # JOSE::JWE callbacks

  def self.from_map(fields)
    bits = nil
    cipher_name = nil
    case fields['alg']
    when 'XC20PKW'
      bits = 256
      cipher_name = 'xchacha20-poly1305'
    else
      raise ArgumentError, "invalid 'alg' for JWE: #{fields['alg'].inspect}"
    end
    iv = nil
    if fields.has_key?('iv')
      iv = JOSE.urlsafe_decode64(fields['iv'])
    end
    tag = nil
    if fields.has_key?('tag')
      tag = JOSE.urlsafe_decode64(fields['tag'])
    end
    return new(cipher_name, bits, iv, tag), fields.except('alg', 'iv', 'tag')
  end

  def to_map(fields)
    alg = algorithm
    fields = fields.put('alg', alg)
    if iv
      fields = fields.put('iv', JOSE.urlsafe_encode64(iv))
    end
    if tag
      fields = fields.put('tag', JOSE.urlsafe_encode64(tag))
    end
    return fields
  end

  # JOSE::JWE::ALG callbacks

  def generate_key(fields, enc)
    return JOSE::JWE::ALG.generate_key([:oct, bits.div(8)], algorithm, enc.algorithm)
  end

  def key_decrypt(key, enc, encrypted_key)
    if iv.nil? or tag.nil?
      raise ArgumentError, "missing required fields for decryption: 'iv' and 'tag'"
    end
    if key.is_a?(JOSE::JWK)
      key = key.kty.derive_key
    end
    derived_key = key
    aad = ''
    cipher_text = encrypted_key
    cipher_tag = tag
    plain_text = JOSE.xchacha20poly1305_module().xchacha20poly1305_aead_decrypt(derived_key, iv, aad, cipher_text, cipher_tag)
    return plain_text
  end

  def key_encrypt(key, enc, decrypted_key)
    if key.is_a?(JOSE::JWK)
      key = key.kty.derive_key
    end
    new_alg = JOSE::JWE::ALG_XC20P_KW.new(cipher_name, bits, iv || SecureRandom.random_bytes(24))
    derived_key = key
    aad = ''
    plain_text = decrypted_key
    cipher_text, new_alg.tag = JOSE.xchacha20poly1305_module().xchacha20poly1305_aead_encrypt(key, new_alg.iv, aad, plain_text)
    return cipher_text, new_alg
  end

  def next_cek(key, enc)
    return enc.next_cek, self
  end

  # API functions

  def algorithm
    case bits
    when 256
      'XC20PKW'
    else
      raise ArgumentError, "unhandled JOSE::JWE::ALG_XC20P_KW bits: #{bits.inspect}"
    end
  end

end
