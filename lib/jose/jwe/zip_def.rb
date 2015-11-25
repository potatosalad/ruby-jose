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
    return Zlib.deflate(plain_text)
  end

  def uncompress(cipher_text)
    return Zlib.inflate(cipher_text)
  end

end
