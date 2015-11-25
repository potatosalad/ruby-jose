module JOSE::JWA::PKCS1

  extend self

  def eme_oaep_decode(hash, em, label, k)
    if hash.is_a?(String)
      hash = OpenSSL::Digest.new(hash)
    end
    h_len = hash.digest('').bytesize
    l_hash = hash.digest(label)
    masked_db_len = k - h_len - 1
    em_s = StringIO.new(em)
    y = em_s.getbyte
    if y != 0x00
      raise ArgumentError, "decryption_error"
    end
    masked_seed = em_s.read(h_len)
    masked_db = em_s.read(masked_db_len)
    seed_mask = mgf1(hash, masked_db, h_len)
    seed = exor(masked_seed, seed_mask)
    db_mask = mgf1(hash, seed, k - h_len - 1)
    db = exor(masked_db, db_mask)
    db_s = StringIO.new(db)
    l_hash_prime = db_s.read(h_len)
    if l_hash != l_hash_prime
      raise ArgumentError, "decryption_error"
    end
    db_right = db_s.read
    sep, m = unpad_zero(db_right).unpack('Ca*')
    if sep != 0x01
      raise ArgumentError, "decryption_error"
    end
    return m
  end

  def eme_oaep_encode(hash, dm, label, seed, k)
    if hash.is_a?(String)
      hash = OpenSSL::Digest.new(hash)
    end
    h_len = hash.digest('').bytesize
    m_len = dm.bytesize
    l_hash = hash.digest(label)
    ps_len = (k - m_len - (2 * h_len) - 2)
    ps = if ps_len > 0
      ([0] * ps_len).pack('C*')
    else
      ''
    end
    db = [l_hash, ps, 0x01, dm].pack('a*a*Ca*')
    db_mask = mgf1(hash, seed, k - h_len - 1)
    masked_db = exor(db, db_mask)
    seed_mask = mgf1(hash, masked_db, h_len)
    masked_seed = exor(seed, seed_mask)
    em = [0x00, masked_seed, masked_db].pack('Ca*a*')
    return em
  end

  def emsa_pss_encode(hash, message, salt, em_bits)
    if hash.is_a?(String)
      hash = OpenSSL::Digest.new(hash)
    end
    salt ||= -2
    if salt.is_a?(Integer)
      salt_len = salt
      if salt_len == -2
        hash_len = hash.digest('').bytesize
        em_len = (em_bits / 8.0).ceil
        salt_len = em_len - hash_len - 2
        if salt_len < 0
          raise ArgumentError, "encoding_error"
        end
      elsif salt_len == -1
        hash_len = hash.digest('').bytesize
        salt_len = hash_len
      end
      if salt_len < 0
        raise ArgumentError, "unhandled salt length: #{salt_len.inspect}"
      end
      salt = SecureRandom.random_bytes(salt_len)
    end
    m_hash = hash.digest(message)
    hash_len = m_hash.bytesize
    salt_len = salt.bytesize
    em_len = (em_bits / 8.0).ceil
    if em_len < (hash_len + salt_len + 2)
      raise ArgumentError, "encoding_error"
    else
      m_prime = [0x00].pack('Q').concat(m_hash).concat(salt)
      h = hash.digest(m_prime)
      ps = ([0x00] * (em_len - salt_len - hash_len - 2)).pack('C*')
      db = [ps, 0x01, salt].pack('a*Ca*')
      db_mask = mgf1(hash, h, em_len - hash_len - 1)
      left_bits = (em_len * 8) - em_bits
      masked_db_right = exor(db, db_mask).unpack('B*')[0][left_bits..-1]
      masked_db = [('0' * left_bits).concat(masked_db_right)].pack('B*')
      em = [masked_db, h, 0xBC].pack('a*a*C')
      return em
    end
  end

  def emsa_pss_verify(hash, message, em, salt_len, em_bits)
    if hash.is_a?(String)
      hash = OpenSSL::Digest.new(hash)
    end
    salt_len ||= -2
    if salt_len == -2
      hash_len = hash.digest('').bytesize
      em_len = (em_bits / 8.0).ceil
      salt_len = em_len - hash_len - 2
      if salt_len < 0
        return false
      end
    elsif salt_len == -1
      hash_len = hash.digest('').bytesize
      salt_len = hash_len
    end
    if salt_len < 0
      raise ArgumentError, "unhandled salt length: #{salt_len.inspect}"
    end
    m_hash = hash.digest(message)
    hash_len = m_hash.bytesize
    em_len = (em_bits / 8.0).ceil
    masked_db_len = (em_len - hash_len - 1)
    if (em.bytesize != em_len) or (em_len < (hash_len + salt_len + 2))
      return false
    else
      em_s = StringIO.new(em)
      masked_db = em_s.read(masked_db_len)
      h = em_s.read(hash_len)
      if em_s.getbyte != 0xBC
        return false
      end
      left_bits = ((em_len * 8) - em_bits)
      if (left_bits > 0) and (masked_db.unpack("B#{left_bits}").pack('B*').unpack('C')[0] != 0x00)
        return false
      end
      db_mask = mgf1(hash, h, em_len - hash_len - 1) rescue nil
      if db_mask.nil?
        return false
      end
      db_right = exor(masked_db, db_mask).unpack('B*')[0][left_bits..-1]
      db = [('0' * left_bits).concat(db_right)].pack('B*')
      ps_len = (em_len - hash_len - salt_len - 2)
      db_s = StringIO.new(db)
      ps = OpenSSL::BN.new(db_s.read(ps_len), 2)
      if ps != 0
        return false
      end
      sep = db_s.getbyte
      if sep != 0x01
        return false
      end
      salt = db_s.read(salt_len)
      m_prime = [0x00].pack('Q').concat(m_hash).concat(salt)
      h_prime = hash.digest(m_prime)
      return h == h_prime
    end
  end

  def mgf1(hash, seed, mask_len)
    hash_len = hash.digest('').bytesize
    if mask_len > (0xFFFFFFFF * hash_len)
      raise ArgumentError, "mask_too_long"
    else
      reps = (mask_len / hash_len.to_f).ceil
      return derive_mgf1(hash, 0, reps, seed, mask_len, '')
    end
  end

  def rsaes_oaep_decrypt(hash, cipher_text, rsa_private_key, label = nil)
    if hash.is_a?(String)
      hash = OpenSSL::Digest.new(hash)
    end
    label ||= ''
    h_len = hash.digest('').bytesize
    k = rsa_private_key.n.num_bytes
    if cipher_text.bytesize != k or k < ((2 * h_len) + 2)
      raise ArgumentError, "decryption_error"
    end
    em = pad_to_key_size(k, dp(OpenSSL::BN.new(cipher_text, 2), rsa_private_key).to_s(2))
    return eme_oaep_decode(hash, em, label, k)
  end

  def rsaes_oaep_encrypt(hash, plain_text, rsa_public_key, label = nil, seed = nil)
    if hash.is_a?(String)
      hash = OpenSSL::Digest.new(hash)
    end
    label ||= ''
    h_len = hash.digest('').bytesize
    seed ||= SecureRandom.random_bytes(h_len)
    m_len = plain_text.bytesize
    k = rsa_public_key.n.num_bytes
    if m_len > (k - (2 * h_len) - 2)
      raise ArgumentError, "message_too_long"
    else
      em = eme_oaep_encode(hash, plain_text, label, seed, k)
      c = pad_to_key_size(k, ep(OpenSSL::BN.new(em, 2), rsa_public_key).to_s(2))
      return c
    end
  end

  def rsassa_pss_sign(hash, message, rsa_private_key, salt = nil)
    mod_bits = rsa_private_key.n.num_bits
    em = emsa_pss_encode(hash, message, salt, mod_bits - 1)
    mod_bytes = rsa_private_key.n.num_bytes
    s = pad_to_key_size(mod_bytes, dp(OpenSSL::BN.new(em, 2), rsa_private_key).to_s(2))
    return s
  end

  def rsassa_pss_verify(hash, message, signature, rsa_public_key, salt_len = nil)
    mod_bytes = rsa_public_key.n.num_bytes
    if signature.bytesize != mod_bytes
      return false
    else
      mod_bits = rsa_public_key.n.num_bits
      em = pad_to_key_size(((mod_bits - 1) / 8.0).ceil, ep(OpenSSL::BN.new(signature, 2), rsa_public_key).to_s(2))
      return emsa_pss_verify(hash, message, em, salt_len, mod_bits - 1)
    end
  end

private

  def derive_mgf1(hash, counter, reps, seed, mask_len, t)
    if counter == reps
      return t[0...mask_len]
    else
      counter_bin = [counter].pack('N')
      new_t = [t, hash.digest([seed, counter_bin].pack('a*a*'))].pack('a*a*')
      return derive_mgf1(hash, counter + 1, reps, seed, mask_len, new_t)
    end
  end

  def dp(b, rsa)
    return b.mod_exp(rsa.d, rsa.n)
  end

  def ep(b, rsa)
    return b.mod_exp(rsa.e, rsa.n)
  end

  def exor(d1, d2)
    if d1.bytesize != d2.bytesize
      raise ArgumentError, "'d1' and 'd2' must have the same bytesize"
    end
    d1 = d1.unpack('C*')
    d2 = d2.unpack('C*')
    d1.length.times do |i|
      d1[i] ^= d2[i]
    end
    return d1.pack('C*')
  end

  def pad_to_key_size(bytes, data)
    if data.bytesize < bytes
      return pad_to_key_size(bytes, [0x00].pack('C').concat(data))
    else
      return data
    end
  end

  def unpad_zero(binary)
    if binary.getbyte(0) == 0x00
      return unpad_zero(binary[1..-1])
    else
      return binary
    end
  end

end
