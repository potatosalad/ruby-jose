module JOSE::JWA::AES_KW

  extend self

  DEFAULT_IV = OpenSSL::BN.new(0xA6A6A6A6A6A6A6A6).to_s(2)

  def unwrap(cipher_text, kek, iv = nil)
    iv ||= DEFAULT_IV
    bits = kek.bytesize * 8
    if cipher_text.bytesize % 8 == 0 and (bits == 128 or bits == 192 or bits == 256)
      block_count = cipher_text.bytesize.div(8) - 1
      buffer = do_unwrap(cipher_text, 5, block_count, kek, bits)
      buffer_s = StringIO.new(buffer)
      if buffer_s.read(iv.bytesize) != iv
        raise ArgumentError, "iv does not match"
      else
        plain_text = buffer_s.read
        return plain_text
      end
    else
      raise ArgumentError, "bad cipher_text, kek, or iv"
    end
  end

  def wrap(plain_text, kek, iv = nil)
    iv ||= DEFAULT_IV
    bits = kek.bytesize * 8
    if plain_text.bytesize % 8 == 0 and (bits == 128 or bits == 192 or bits == 256)
      buffer = [iv, plain_text].join
      block_count = buffer.bytesize.div(8) - 1
      return do_wrap(buffer, 0, block_count, kek, bits)
    else
      raise ArgumentError, "bad plain_text, kek, or iv"
    end
  end

private

  def aes_ecb_decrypt(bits, key, cipher_text)
    cipher = OpenSSL::Cipher::AES.new(bits, :ECB)
    cipher.decrypt
    cipher.key = key
    cipher.padding = 0
    return cipher.update(cipher_text) + cipher.final
  end

  def aes_ecb_encrypt(bits, key, plain_text)
    cipher = OpenSSL::Cipher::AES.new(bits, :ECB)
    cipher.encrypt
    cipher.key = key
    cipher.padding = 0
    return cipher.update(plain_text) + cipher.final
  end

  def do_unwrap(buffer, j, block_count, kek, bits)
    if j < 0
      return buffer
    else
      return do_unwrap(do_unwrap_step(buffer, j, block_count, block_count, kek, bits), j - 1, block_count, kek, bits)
    end
  end

  def do_unwrap_step(buffer, j, i, block_count, kek, bits)
    if i < 1
      return buffer
    end
    buffer_s = StringIO.new(buffer)
    a0, = buffer_s.read(8).unpack('Q>')
    head_size = (i - 1) * 8
    head = buffer_s.read(head_size)
    b0 = buffer_s.read(8)
    tail = buffer_s.read
    round = (block_count * j) + i
    a1 = a0 ^ round
    data = [a1, b0].pack('Q>a*')
    a2, b1 = aes_ecb_decrypt(bits, kek, data).unpack('Q>a*')
    return do_unwrap_step([a2, head, b1, tail].pack('Q>a*a*a*'), j, i - 1, block_count, kek, bits)
  end

  def do_wrap(buffer, j, block_count, kek, bits)
    if j == 6
      return buffer
    else
      return do_wrap(do_wrap_step(buffer, j, 1, block_count, kek, bits), j + 1, block_count, kek, bits)
    end
  end

  def do_wrap_step(buffer, j, i, block_count, kek, bits)
    if i > block_count
      return buffer
    end
    buffer_s = StringIO.new(buffer)
    a0 = buffer_s.read(8)
    head_size = (i - 1) * 8
    head = buffer_s.read(head_size)
    b0 = buffer_s.read(8)
    tail = buffer_s.read
    round = (block_count * j) + i
    data = [a0, b0].join
    a1, b1 = aes_ecb_encrypt(bits, kek, data).unpack('Q>a*')
    a2 = a1 ^ round
    return do_wrap_step([a2, head, b1, tail].pack('Q>a*a*a*'), j, i + 1, block_count, kek, bits)
  end

end
