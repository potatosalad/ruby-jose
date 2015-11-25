class JOSE::JWE::ALG_dir

  # JOSE::JWE callbacks

  def self.from_map(fields)
    case fields['alg']
    when 'dir'
      return new(), fields.delete('alg')
    else
      raise ArgumentError, "invalid 'alg' for JWE: #{fields['alg'].inspect}"
    end
  end

  def to_map(fields)
    return fields.put('alg', 'dir')
  end

  # JOSE::JWE::ALG callbacks

  def key_decrypt(key, enc, encrypted_key)
    if key.is_a?(String)
      return key
    else
      return key.kty.derive_key
    end
  end

  def key_encrypt(key, enc, decrypted_key)
    return '', self
  end

  def next_cek(key, enc)
    if key.is_a?(String)
      return key
    else
      return key.kty.derive_key
    end
  end

end
