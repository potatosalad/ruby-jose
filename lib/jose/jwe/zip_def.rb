class JOSE::JWE::ZIP_DEF

  # JOSE::JWE callbacks

  def self.from_map(fields)
    case fields['zip']
    when 'DEF'
      return new(), fields.except('zip')
    else
      raise ArgumentError, "invalid 'zip' for JWE: #{fields['zip'].inspect}"
    end
  end

  def to_map(fields)
    return fields.put('zip', 'DEF')
  end

  # JOSE::JWE::ZIP callbacks

  def compress(plain_text)
    zstream = Zlib::Deflate.new(nil, -Zlib::MAX_WBITS)
    buf = zstream.deflate(plain_text, Zlib::FINISH)
    zstream.finish
    zstream.close
    return buf
  end

  def uncompress(cipher_text)
    zstream = Zlib::Inflate.new(-Zlib::MAX_WBITS)
    buf = zstream.inflate(cipher_text)
    zstream.finish
    zstream.close
    return buf
  end

end
