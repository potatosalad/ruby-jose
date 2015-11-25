module JOSE::JWK::PEM

  extend self

  def from_binary(object, password = nil)
    pkey = OpenSSL::PKey.read(object, password)
    return JOSE::JWK::KTY.from_key(pkey)
  end

  def to_binary(key, password = nil)
    if password
      cipher = OpenSSL::Cipher.new('DES-EDE3-CBC')
      return key.to_pem(cipher, password)
    else
      return key.to_pem
    end
  end

end
