class JOSE::JWE::ALG_dir < Struct.new(:direct)

  # JOSE::JWE callbacks

  def self.from_map(fields)
    case fields['alg']
    when 'dir'
      return new(true), fields.delete('alg')
    else
      raise ArgumentError, "invalid 'alg' for JWE: #{fields['alg'].inspect}"
    end
  end

  def to_map(fields)
    return fields.put('alg', 'dir')
  end

  # JOSE::JWE::ALG callbacks

  def generate_key(fields, enc)
    return JOSE::JWE::ALG.generate_key([:oct, enc.bits.div(8)], 'dir', enc.algorithm)
  end

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
      return key, self
    else
      return key.kty.derive_key, self
    end
  end

end
