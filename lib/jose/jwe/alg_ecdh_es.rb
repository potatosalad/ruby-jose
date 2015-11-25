class JOSE::JWE::ALG_ECDH_ES < Struct.new(:bits, :epk, :apu, :apv)

  # JOSE::JWE callbacks

  def self.from_map(fields)
    bits = nil
    case fields['alg']
    when 'ECDH-ES'
      bits = nil
    when 'ECDH-ES+A128KW'
      bits = 128
    when 'ECDH-ES+A192KW'
      bits = 192
    when 'ECDH-ES+A256KW'
      bits = 256
    else
      raise ArgumentError, "invalid 'alg' for JWE: #{fields['alg'].inspect}"
    end
    epk = nil
    if fields.has_key?('epk')
      epk = JOSE::JWK.from_map(fields['epk'])
    end
    apu = nil
    if fields.has_key?('apu')
      apu = JOSE.urlsafe_decode64(fields['apu'])
    end
    apv = nil
    if fields.has_key?('apv')
      apv = JOSE.urlsafe_decode64(fields['apv'])
    end
    return new(bits, epk, apu, apv), fields.except('alg', 'apu', 'apv', 'epk')
  end

  def to_map(fields)
    fields = fields.put('alg', algorithm)
    if epk
      fields = fields.put('epk', epk.to_map)
    end
    if apu
      fields = fields.put('apu', JOSE.urlsafe_encode64(apu))
    end
    if apv
      fields = fields.put('apv', JOSE.urlsafe_encode64(apv))
    end
    return fields
  end

  # JOSE::JWE::ALG callbacks

  def key_decrypt(box_keys, enc, encrypted_key)
    other_public_key, my_private_key = box_keys
    if my_private_key and epk and epk.to_key != other_public_key.to_key
      raise ArgumentError, "other and ephemeral public key mismatch"
    elsif epk and my_private_key.nil?
      my_private_key = other_public_key
      other_public_key = epk
    else
      raise ArgumentError, "missing 'epk' or my_private_key"
    end
    z = other_public_key.derive_key(my_private_key)
    if bits.nil?
      algorithm_id = enc.algorithm
      key_data_len = enc.bits
      supp_pub_info = [key_data_len].pack('N')
      derived_key = JOSE::JWA::ConcatKDF.kdf(OpenSSL::Digest::SHA256, z, [algorithm_id, apu, apv, supp_pub_info], key_data_len)
      return derived_key
    else
      algorithm_id = algorithm
      key_data_len = bits
      supp_pub_info = [key_data_len].pack('N')
      derived_key = JOSE::JWA::ConcatKDF.kdf(OpenSSL::Digest::SHA256, z, [algorithm_id, apu, apv, supp_pub_info], key_data_len)
      decrypted_key = JOSE::JWA::AES_KW.unwrap(encrypted_key, derived_key)
      return decrypted_key
    end
  end

  def key_encrypt(box_keys, enc, decrypted_key)
    if bits.nil?
      return '', self
    else
      other_public_key, my_private_key = box_keys
      z = other_public_key.derive_key(my_private_key)
      algorithm_id = algorithm
      key_data_len = bits
      supp_pub_info = [key_data_len].pack('N')
      derived_key = JOSE::JWA::ConcatKDF.kdf(OpenSSL::Digest::SHA256, z, [algorithm_id, apu, apv, supp_pub_info], key_data_len)
      encrypted_key = JOSE::JWA::AES_KW.wrap(decrypted_key, derived_key)
      return encrypted_key, self
    end
  end

  def next_cek(box_keys, enc)
    if bits.nil?
      other_public_key, my_private_key = box_keys
      z = other_public_key.derive_key(my_private_key)
      algorithm_id = enc.algorithm
      key_data_len = enc.bits
      supp_pub_info = [key_data_len].pack('N')
      derived_key = JOSE::JWA::ConcatKDF.kdf(OpenSSL::Digest::SHA256, z, [algorithm_id, apu, apv, supp_pub_info], key_data_len)
      return derived_key
    else
      return enc.next_cek
    end
  end

  # API functions

  def algorithm
    case bits
    when nil
      return 'ECDH-ES'
    when 128
      return 'ECDH-ES+A128KW'
    when 192
      return 'ECDH-ES+A192KW'
    when 256
      return 'ECDH-ES+A256KW'
    else
      raise ArgumentError, "unhandled JOSE::JWE::ALG_ECDH_ES bits: #{bits.inspect}"
    end
  end

end
