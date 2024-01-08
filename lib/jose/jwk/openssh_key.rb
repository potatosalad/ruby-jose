module JOSE::JWK::OpenSSHKey

  extend self

  def from_binary(binary, password = nil)
    return parse_keys(StringIO.new(binary))
  end

  def to_binary(list, password = nil)
    return list.flat_map do |key_list|
      next [
        "-----BEGIN OPENSSH PRIVATE KEY-----\n",
        chunk(Base64.encode64(write_keylist(*key_list.transpose)), 70),
        "-----END OPENSSH PRIVATE KEY-----\n"
      ]
    end.join
  end

private

  # Internal encode functions

  def chunk(binary, size)
    return binary.gsub(/[\r\n]/, '').scan(/.{0,#{size}}/).join("\n")
  end

  def write_keylist(pks, sks)
    raise ArgumentError, "pk list and sk list lengths do not match" if pks.length != sks.length
    n = pks.length
    pk_bin = write_publickeys(pks)
    sk_bin = write_secretkeys(sks)
    check = SecureRandom.random_bytes(4)
    unpadded = [check, check, sk_bin].pack('a4a4a*')
    padded = add_padding(unpadded, 0)
    cipher_name = 'none'
    cipher_name_len = cipher_name.bytesize
    kdf_name = 'none'
    kdf_name_len = kdf_name.bytesize
    kdf_options = ''
    kdf_options_len = kdf_options.bytesize
    padded_len = padded.bytesize
    return [
      'openssh-key-v1',
      0x00,
      cipher_name_len,
      cipher_name,
      kdf_name_len,
      kdf_name,
      kdf_options_len,
      kdf_options,
      n,
      pk_bin,
      padded_len,
      padded
    ].pack("a*CNa#{cipher_name_len}Na#{kdf_name_len}Na#{kdf_options_len}Na*Na#{padded_len}")
  end

  def write_publickeys(pks)
    return pks.map do |pk|
      type, key = pk
      if type and key
        type_len = type.bytesize
        key_len = key.bytesize
        pk = [
          type_len,
          type,
          key_len,
          key
        ].pack("Na#{type_len}Na#{key_len}")
      end
      pk_size = pk.bytesize
      next [
        pk_size,
        pk
      ].pack("Na#{pk_size}")
    end.join
  end

  def write_secretkeys(sks)
    return sks.map do |(type, pk, sk, comment)|
      type_len = type.bytesize
      pk_len = pk.bytesize
      sk_len = sk.bytesize
      comment_len = comment.bytesize
      next [
        type_len,
        type,
        pk_len,
        pk,
        sk_len,
        sk,
        comment_len,
        comment
      ].pack("Na#{type_len}Na#{pk_len}Na#{sk_len}Na#{comment_len}")
    end.join
  end

  def add_padding(u, p)
    return add_padding(u, p + 1) if (u.bytesize + p) % 8 != 0
    return [
      u,
      *(1..p).to_a
    ].pack("a*C#{p}")
  end

  # Internal decode functions

  def parse_keys(buffer, keys = [])
    pos = buffer.pos
    chr = buffer.getc
    if chr.nil?
      return keys
    elsif chr == '-'
      if buffer.read(34) == '----BEGIN OPENSSH PRIVATE KEY-----'
        key, rest = parse_key(buffer)
        keys.push(key) if key
        return parse_keys(rest, keys)
      else
        buffer.pos = pos + 1
        return parse_keys(buffer, keys)
      end
    else
      return parse_keys(buffer, keys)
    end
  end

  def parse_key(buffer, body = StringIO.new)
    pos = buffer.pos
    chr = buffer.getc
    if chr.nil?
      return nil, buffer
    elsif chr == "\r" or chr == "\n" or chr == "\s" or chr == "\t"
      return parse_key(buffer, body)
    elsif chr == '-'
      if buffer.read(32) == '----END OPENSSH PRIVATE KEY-----'
        key = parse_key_body(StringIO.new(Base64.decode64(body.string)))
        return key, buffer
      else
        buffer.pos = pos + 1
        return parse_key(buffer, body)
      end
    else
      body.write(chr)
      return parse_key(buffer, body)
    end
  end

  def parse_key_body(body)
    pos = body.pos
    chr = body.getc
    if chr.nil?
      return nil
    elsif chr == 'o' and body.read(13) == 'penssh-key-v1' and body.getbyte == 0
      if cipher_name_len = body.read(4) and cipher_name_len.bytesize == 4
        cipher_name_len, = cipher_name_len.unpack('N')
        if cipher_name = body.read(cipher_name_len) and cipher_name.bytesize == cipher_name_len
          if kdf_name_len = body.read(4) and kdf_name_len.bytesize == 4
            kdf_name_len, = kdf_name_len.unpack('N')
            if kdf_name = body.read(kdf_name_len) and kdf_name.bytesize == kdf_name_len
              if kdf_options_len = body.read(4) and kdf_options_len.bytesize == 4
                kdf_options_len, = kdf_options_len.unpack('N')
                if kdf_options = body.read(kdf_options_len) and kdf_options.bytesize == kdf_options_len
                  if n = body.read(4) and n.bytesize == 4
                    n, = n.unpack('N')
                    pks, enc = parse_publickeys(body, n)
                    return nil if pks.nil?
                    if encrypted_len = enc.read(4) and encrypted_len.bytesize == 4
                      encrypted_len, = encrypted_len.unpack('N')
                      if encrypted = enc.read(encrypted_len) and encrypted.bytesize == encrypted_len
                        header = [cipher_name, kdf_name, kdf_options, n]
                        key = maybe_parse_secretkeys(header, pks, StringIO.new(encrypted))
                        if key
                          return key
                        else
                          return [header, pks, encrypted]
                        end
                      end
                    end
                  end
                end
              end
            end
          end
        end
      end
    end
    body.pos = pos + 1
    return parse_key_body(body)
  end

  def parse_publickeys(body, n, pks = [])
    return pks, body if n == 0
    if pk_len = body.read(4) and pk_len.bytesize == 4
      pk_len, = pk_len.unpack('N')
      if pk = body.read(pk_len) and pk.bytesize == pk_len
        pk = StringIO.new(pk)
        if type_len = pk.read(4) and type_len.bytesize == 4
          type_len, = type_len.unpack('N')
          if type = pk.read(type_len) and type.bytesize == type_len
            if key_len = pk.read(4) and key_len.bytesize == 4
              key_len, = key_len.unpack('N')
              if key = pk.read(key_len) and key.bytesize == key_len
                pks.push([type, key])
                return parse_publickeys(body, n - 1, pks)
              end
            end
          end
        end
        pks.push(pk.string)
        return parse_publickeys(body, n - 1, pks)
      end
    end
    return nil
  end

  def maybe_parse_secretkeys(header, pks, encrypted)
    cipher_name, kdf_name, kdf_options, n = header
    if cipher_name == 'none' and kdf_name == 'none' and kdf_options == ''
      if check1 = encrypted.read(4) and check1.bytesize == 4 and
          check2 = encrypted.read(4) and check2.bytesize == 4 and
          check1 == check2
        sks = parse_secretkeys(del_padding(encrypted), n)
        if sks
          return pks.zip(sks)
        end
      end
    end
    return nil
  end

  def del_padding(padded)
    return StringIO.new if padded.eof?
    padded = padded.read
    padding = padded.getbyte(-1)
    if padding > padded.bytesize
      return StringIO.new
    else
      while padding > 0
        if padded.getbyte(-1) == padding
          padded.chop!
          padding = padding - 1
        else
          return StringIO.new
        end
      end
      return StringIO.new(padded)
    end
  end

  def parse_secretkeys(buffer, n, sks = [])
    return sks if n == 0
    if type_len = buffer.read(4) and type_len.bytesize == 4
      type_len, = type_len.unpack('N')
      if type = buffer.read(type_len) and type.bytesize == type_len
        if pk_len = buffer.read(4) and pk_len.bytesize == 4
          pk_len, = pk_len.unpack('N')
          if pk = buffer.read(pk_len) and pk.bytesize == pk_len
            if sk_len = buffer.read(4) and sk_len.bytesize == 4
              sk_len, = sk_len.unpack('N')
              if sk = buffer.read(sk_len) and sk.bytesize == sk_len
                if comment_len = buffer.read(4) and comment_len.bytesize == 4
                  comment_len, = comment_len.unpack('N')
                  if comment = buffer.read(comment_len) and comment.bytesize == comment_len
                    sks.push([type, pk, sk, comment])
                    return parse_secretkeys(buffer, n - 1, sks)
                  end
                end
              end
            end
          end
        end
      end
    end
    return nil
  end

end
