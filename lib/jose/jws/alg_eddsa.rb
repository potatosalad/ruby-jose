class JOSE::JWS::ALG_EDDSA < Struct.new(:sign_type)

  # JOSE::JWS callbacks

  def self.from_map(fields)
    case fields['alg']
    when 'Ed25519'
      return new(:Ed25519), fields.delete('alg')
    when 'Ed25519ph'
      return new(:Ed25519ph), fields.delete('alg')
    when 'Ed448'
      return new(:Ed448), fields.delete('alg')
    when 'Ed448ph'
      return new(:Ed448ph), fields.delete('alg')
    else
      raise ArgumentError, "invalid 'alg' for JWS: #{fields['alg'].inspect}"
    end
  end

  def to_map(fields)
    alg = sign_type.to_s
    return fields.put('alg', alg)
  end

  # JOSE::JWS::ALG callbacks

  def sign(jwk, message)
    return jwk.kty.sign(message, sign_type)
  end

  def verify(jwk, message, signature)
    return jwk.kty.verify(message, sign_type, signature)
  end

end
