class JOSE::JWK::KTY_oct < Struct.new(:oct)

  # JOSE::JWK callbacks

  def self.from_map(fields)
    if fields['kty'] == 'oct' and fields['k'].is_a?(String)
      return JOSE::JWK::KTY_oct.new(JOSE.urlsafe_decode64(fields['k'])), fields.except('kty', 'k')
    else
      raise ArgumentError, "invalid 'oct' JWK"
    end
  end

  def to_key
    return oct
  end

  def to_map(fields)
    return fields.put('k', JOSE.urlsafe_encode64(oct)).put('kty', 'oct')
  end

  def to_public_map(fields)
    return to_map(fields)
  end

  def to_thumbprint_map(fields)
    return to_public_map(fields).slice('k', 'kty')
  end

  # JOSE::JWK::KTY callbacks

  def block_encryptor(fields, plain_text)
    enc = case (oct.bytesize * 8)
    when 128
      'A128GCM'
    when 192
      'A192GCM'
    when 256
      'A256GCM'
    when 384
      'A192CBC-HS384'
    when 512
      'A256CBC-HS512'
    else
      raise ArgumentError, "oct of size #{oct.bytesize * 8} has no default block encryptor"
    end
    return JOSE::Map[
      'alg' => 'dir',
      'enc' => enc
    ]
  end

  def derive_key
    return oct
  end

  def self.generate_key(size)
    if size.is_a?(Array) and size.length == 2 and size[0] == :oct
      size = size[1]
    end
    case size
    when Integer
      return from_oct(SecureRandom.random_bytes(size))
    else
      raise ArgumentError, "'size' must be an Integer"
    end
  end

  def generate_key(fields)
    kty, other_fields = JOSE::JWK::KTY_oct.generate_key(oct.bytesize)
    return kty, fields.delete('kid').merge(other_fields)
  end

  def key_encryptor(fields, key)
    return JOSE::JWK::KTY.key_encryptor(self, fields, key)
  end

  def sign(message, digest_type)
    return OpenSSL::HMAC.digest(digest_type.new, oct, message)
  end

  def signer(fields = nil, plain_text = nil)
    return JOSE::Map['alg' => 'HS256']
  end

  def verify(message, digest_type, signature)
    return JOSE::JWA.constant_time_compare(signature, sign(message, digest_type))
  end

  # API functions

  def self.from_oct(binary)
    case binary
    when String
      return JOSE::JWK::KTY_oct.new(binary), JOSE::Map[]
    else
      raise ArgumentError, "'binary' must be a String"
    end
  end

  def to_oct
    return oct
  end

end
