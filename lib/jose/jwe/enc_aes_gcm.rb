class JOSE::JWE::ENC_AES_GCM < Struct.new(:cipher_name, :bits, :cek_len, :iv_len)

  # JOSE::JWE callbacks

  def self.from_map(fields)
    case fields['enc']
    when 'A128GCM'
      return new('aes-128-gcm', 128, 16, 12), fields.delete('enc')
    when 'A192GCM'
      return new('aes-192-gcm', 192, 24, 12), fields.delete('enc')
    when 'A256GCM'
      return new('aes-256-gcm', 256, 32, 12), fields.delete('enc')
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
    when 'aes-128-gcm'
      return 'A128GCM'
    when 'aes-192-gcm'
      return 'A192GCM'
    when 'aes-256-gcm'
      return 'A256GCM'
    else
      raise ArgumentError, "unhandled JOSE::JWE::ENC_AES_GCM cipher name: #{cipher_name.inspect}"
    end
  end

  def block_decrypt(aad_cipher_text_cipher_tag, cek, iv)
    aad, cipher_text, cipher_tag = aad_cipher_text_cipher_tag
    cipher = OpenSSL::Cipher.new(cipher_name)
    cipher.decrypt
    cipher.key = cek
    cipher.iv = iv
    cipher.padding = 0
    cipher.auth_data = aad
    cipher.auth_tag = cipher_tag
    plain_text = cipher.update(cipher_text) + cipher.final
    return plain_text
  end

  def block_encrypt(aad_plain_text, cek, iv)
    aad, plain_text = aad_plain_text
    cipher = OpenSSL::Cipher.new(cipher_name)
    cipher.encrypt
    cipher.key = cek
    cipher.iv = iv
    cipher.padding = 0
    cipher.auth_data = aad
    cipher_text = cipher.update(plain_text) + cipher.final
    return cipher_text, cipher.auth_tag
  end

  def next_cek
    return SecureRandom.random_bytes(cek_len)
  end

  def next_iv
    return SecureRandom.random_bytes(iv_len)
  end

end
