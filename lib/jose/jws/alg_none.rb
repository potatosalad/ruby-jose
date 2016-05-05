class JOSE::JWS::ALG_none < Struct.new(:none)

  # JOSE::JWS callbacks

  def self.from_map(fields)
    case fields['alg']
    when 'none'
      return new(true), fields.delete('alg')
    else
      raise ArgumentError, "invalid 'alg' for JWS: #{fields['alg'].inspect}"
    end
  end

  def to_map(fields)
    return fields.put('alg', 'none')
  end

  # JOSE::JWS::ALG callbacks

  def generate_key(fields)
    raise NotImplementedError
  end

  def sign(jwk, message)
    if JOSE.__unsecured_signing__
      return ''
    else
      raise NotImplementedError
    end
  end

  def verify(jwk, message, signature)
    if JOSE.__unsecured_signing__
      if signature == ''
        return true
      else
        return false
      end
    else
      raise NotImplementedError
    end
  end

end
