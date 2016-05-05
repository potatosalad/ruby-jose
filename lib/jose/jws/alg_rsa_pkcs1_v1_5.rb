class JOSE::JWS::ALG_RSA_PKCS1_V1_5 < Struct.new(:digest)

  # JOSE::JWS callbacks

  def self.from_map(fields)
    case fields['alg']
    when 'RS256'
      return new(OpenSSL::Digest::SHA256), fields.delete('alg')
    when 'RS384'
      return new(OpenSSL::Digest::SHA384), fields.delete('alg')
    when 'RS512'
      return new(OpenSSL::Digest::SHA512), fields.delete('alg')
    else
      raise ArgumentError, "invalid 'alg' for JWS: #{fields['alg'].inspect}"
    end
  end

  def to_map(fields)
    alg = if digest == OpenSSL::Digest::SHA256
      'RS256'
    elsif digest == OpenSSL::Digest::SHA384
      'RS384'
    elsif digest == OpenSSL::Digest::SHA512
      'RS512'
    else
      raise ArgumentError, "unhandled RSA_PKCS1_v1_5 digest type: #{digest.inspect}"
    end
    return fields.put('alg', alg)
  end

  # JOSE::JWS::ALG callbacks

  def generate_key(fields)
    bitsize, alg = if digest == OpenSSL::Digest::SHA256
      [2048, 'RS256']
    elsif digest == OpenSSL::Digest::SHA384
      [3072, 'RS384']
    elsif digest == OpenSSL::Digest::SHA512
      [4096, 'RS512']
    else
      raise ArgumentError, "unhandled RSA_PKCS1_v1_5 digest type: #{digest.inspect}"
    end
    return JOSE::JWS::ALG.generate_key([:rsa, bitsize], alg)
  end

  def sign(jwk, message)
    return jwk.kty.sign(message, digest, padding: :rsa_pkcs1_padding)
  end

  def verify(jwk, message, signature)
    return jwk.kty.verify(message, digest, signature, padding: :rsa_pkcs1_padding)
  end

end
