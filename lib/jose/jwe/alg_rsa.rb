class JOSE::JWE::ALG_RSA < Struct.new(:rsa_padding, :rsa_oaep_md)

  # JOSE::JWE callbacks

  def self.from_map(fields)
    rsa_padding = nil
    rsa_oaep_md = nil
    case fields['alg']
    when 'RSA1_5'
      rsa_padding = :rsa_pkcs1_padding
    when 'RSA-OAEP'
      rsa_padding = :rsa_pkcs1_oaep_padding
      rsa_oaep_md = OpenSSL::Digest::SHA1
    when 'RSA-OAEP-256'
      rsa_padding = :rsa_pkcs1_oaep_padding
      rsa_oaep_md = OpenSSL::Digest::SHA256
    else
      raise ArgumentError, "invalid 'alg' for JWE: #{fields['alg'].inspect}"
    end
    return new(rsa_padding, rsa_oaep_md), fields.except('alg')
  end

  def to_map(fields)
    alg = nil
    if rsa_padding == :rsa_pkcs1_padding
      alg = 'RSA1_5'
    elsif rsa_padding == :rsa_pkcs1_oaep_padding
      if rsa_oaep_md == OpenSSL::Digest::SHA1
        alg = 'RSA-OAEP'
      elsif rsa_oaep_md == OpenSSL::Digest::SHA256
        alg = 'RSA-OAEP-256'
      else
        raise ArgumentError, "unhandled JOSE::JWE::ALG_RSA rsa_oaep_md: #{rsa_oaep_md.inspect}"
      end
    else
      raise ArgumentError, "unhandled JOSE::JWE::ALG_RSA rsa_padding: #{rsa_padding.inspect}"
    end
    return fields.put('alg', alg)
  end

  # JOSE::JWE::ALG callbacks

  def key_decrypt(key, enc, encrypted_key)
    if key.is_a?(JOSE::JWK)
      return key.kty.decrypt_private(encrypted_key, rsa_padding: rsa_padding, rsa_oaep_md: rsa_oaep_md)
    else
      raise ArgumentError, "'key' must be a JOSE::JWK"
    end
  end

  def key_encrypt(key, enc, decrypted_key)
    if key.is_a?(JOSE::JWK)
      return key.kty.encrypt_public(decrypted_key, rsa_padding: rsa_padding, rsa_oaep_md: rsa_oaep_md), self
    else
      raise ArgumentError, "'key' must be a JOSE::JWK"
    end
  end

  def next_cek(key, enc)
    return enc.next_cek
  end

end
