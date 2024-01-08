class JOSE::JWE::ENC_XC20P < Struct.new(:cipher_name, :bits, :cek_len, :iv_len)

  # JOSE::JWE callbacks

  def self.from_map(fields)
    case fields['enc']
    when 'XC20P'
      return new('xchacha20-poly1305', 256, 32, 24), fields.delete('enc')
    else
      raise ArgumentError, "invalid 'enc' for JWE: #{fields['enc'].inspect}"
    end
  end

  def to_map(fields)
    return fields.put('enc', algorithm)
  end

  # JOSE::JWE::ENC callbacks

  def algorithm
    case cipher_name
    when 'xchacha20-poly1305'
      return 'XC20P'
    else
      raise ArgumentError, "unhandled JOSE::JWE::ENC_XC20P cipher name: #{cipher_name.inspect}"
    end
  end

  def block_decrypt(aad_cipher_text_cipher_tag, cek, iv)
    aad, cipher_text, cipher_tag = aad_cipher_text_cipher_tag
    plain_text = JOSE.xchacha20poly1305_module().xchacha20poly1305_aead_decrypt(cek, iv, aad, cipher_text, cipher_tag)
    return plain_text
  end

  def block_encrypt(aad_plain_text, cek, iv)
    aad, plain_text = aad_plain_text
    cipher_text, cipher_tag = JOSE.xchacha20poly1305_module().xchacha20poly1305_aead_encrypt(cek, iv, aad, plain_text)
    return cipher_text, cipher_tag
  end

  def next_cek
    return SecureRandom.random_bytes(cek_len)
  end

  def next_iv
    return SecureRandom.random_bytes(iv_len)
  end

end
