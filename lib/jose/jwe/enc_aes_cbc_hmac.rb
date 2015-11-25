class JOSE::JWE::ENC_AES_CBC_HMAC < Struct.new(:cipher_name, :bits, :cek_len, :iv_len, :enc_len, :mac_len, :tag_len, :hmac)

  # JOSE::JWE callbacks

  def self.from_map(fields)
    case fields['enc']
    when 'A128CBC-HS256'
      return new('aes-128-cbc', 256, 32, 16, 16, 16, 16, OpenSSL::Digest::SHA256), fields.delete('enc')
    when 'A192CBC-HS384'
      return new('aes-192-cbc', 384, 48, 16, 24, 24, 24, OpenSSL::Digest::SHA384), fields.delete('enc')
    when 'A256CBC-HS512'
      return new('aes-256-cbc', 512, 64, 16, 32, 32, 32, OpenSSL::Digest::SHA512), fields.delete('enc')
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
    when 'aes-128-cbc'
      return 'A128CBC-HS256'
    when 'aes-192-cbc'
      return 'A192CBC-HS384'
    when 'aes-256-cbc'
      return 'A256CBC-HS512'
    else
      raise ArgumentError, "unhandled JOSE::JWE::ENC_AES_CBC_HMAC cipher name: #{cipher_name.inspect}"
    end
  end

  def block_decrypt(aad_cipher_text_cipher_tag, cek, iv)
    aad, cipher_text, cipher_tag = aad_cipher_text_cipher_tag
    cek_s = StringIO.new(cek)
    mac_key = cek_s.read(mac_len)
    enc_key = cek_s.read(enc_len)
    aad_len = [(aad.bytesize * 8)].pack('Q>')
    mac_data = [aad, iv, cipher_text, aad_len].pack('a*a*a*a*')
    if cipher_tag != OpenSSL::HMAC.digest(hmac.new, mac_key, mac_data)[0..tag_len]
      raise ArgumentError, "decryption error"
    else
      cipher = OpenSSL::Cipher.new(cipher_name)
      cipher.decrypt
      cipher.key = cek
      cipher.iv = iv
      plain_text = JOSE::JWA::PKCS7.unpad(cipher.update(cipher_text) + cipher.final)
      return plain_text
    end
  end

  def block_encrypt(aad_plain_text, cek, iv)
    aad, plain_text = aad_plain_text
    cek_s = StringIO.new(cek)
    mac_key = cek_s.read(mac_len)
    enc_key = cek_s.read(enc_len)
    cipher = OpenSSL::Cipher.new(cipher_name)
    cipher.encrypt
    cipher.key = cek
    cipher.iv = iv
    cipher_text = cipher.update(JOSE::JWA::PKCS7.pad(plain_text)) + cipher.final
    aad_len = [(aad.bytesize * 8)].pack('Q>')
    mac_data = [aad, iv, cipher_text, aad_len].pack('a*a*a*a*')
    cipher_tag = OpenSSL::HMAC.digest(hmac.new, mac_key, mac_data)[0..tag_len]
    return cipher_text, cipher_tag
  end

  def next_cek
    return SecureRandom.random_bytes(cek_len)
  end

  def next_iv
    return SecureRandom.random_bytes(iv_len)
  end

end
