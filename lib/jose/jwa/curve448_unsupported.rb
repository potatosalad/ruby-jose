module JOSE::JWA::Curve448_Unsupported

  extend self

  def __ruby__?; true; end
  def __supported__?; false; end

  def ed448_keypair(secret = nil)
    raise NotImplementedError
  end

  def ed448_secret_to_public(sk)
    raise NotImplementedError
  end

  def ed448_sign(m, sk)
    raise NotImplementedError
  end

  def ed448_verify(sig, m, pk)
    raise NotImplementedError
  end

  def ed448ph_keypair(secret = nil)
    raise NotImplementedError
  end

  def ed448ph_secret_to_public(sk)
    raise NotImplementedError
  end

  def ed448ph_sign(m, sk)
    raise NotImplementedError
  end

  def ed448ph_verify(sig, m, pk)
    raise NotImplementedError
  end

  def x448_keypair(secret = nil)
    raise NotImplementedError
  end

  def x448_secret_to_public(sk)
    raise NotImplementedError
  end

  def x448_shared_secret(pk, sk)
    raise NotImplementedError
  end

end
