class JOSE::JWS::ALG_HMAC < Struct.new(:hmac)

  # JOSE::JWS callbacks

  def self.from_map(fields)
    case fields['alg']
    when 'HS256'
      return new(OpenSSL::Digest::SHA256), fields.delete('alg')
    when 'HS384'
      return new(OpenSSL::Digest::SHA384), fields.delete('alg')
    when 'HS512'
      return new(OpenSSL::Digest::SHA512), fields.delete('alg')
    else
      raise ArgumentError, "invalid 'alg' for JWS: #{fields['alg'].inspect}"
    end
  end

  def to_map(fields)
    alg = if hmac == OpenSSL::Digest::SHA256
      'HS256'
    elsif hmac == OpenSSL::Digest::SHA384
      'HS384'
    elsif hmac == OpenSSL::Digest::SHA512
      'HS512'
    else
      raise ArgumentError, "unhandled HMAC digest type: #{hmac.inspect}"
    end
    return fields.put('alg', alg)
  end

  # JOSE::JWS::ALG callbacks

  def sign(jwk, message)
    return jwk.kty.sign(message, hmac)
  end

  def verify(jwk, message, signature)
    return jwk.kty.verify(message, hmac, signature)
  end

end
