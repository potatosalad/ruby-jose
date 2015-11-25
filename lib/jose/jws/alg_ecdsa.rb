class JOSE::JWS::ALG_ECDSA < Struct.new(:digest)

  # JOSE::JWS callbacks

  def self.from_map(fields)
    case fields['alg']
    when 'ES256'
      return new(OpenSSL::Digest::SHA256), fields.delete('alg')
    when 'ES384'
      return new(OpenSSL::Digest::SHA384), fields.delete('alg')
    when 'ES512'
      return new(OpenSSL::Digest::SHA512), fields.delete('alg')
    else
      raise ArgumentError, "invalid 'alg' for JWS: #{fields['alg'].inspect}"
    end
  end

  def to_map(fields)
    alg = if digest == OpenSSL::Digest::SHA256
      'ES256'
    elsif digest == OpenSSL::Digest::SHA384
      'ES384'
    elsif digest == OpenSSL::Digest::SHA512
      'ES512'
    else
      raise ArgumentError, "unhandled ECDSA digest type: #{digest.inspect}"
    end
    return fields.put('alg', alg)
  end

  # JOSE::JWS::ALG callbacks

  def sign(jwk, message)
    return jwk.kty.sign(message, digest)
  end

  def verify(jwk, message, signature)
    return jwk.kty.verify(message, digest, signature)
  end

end
