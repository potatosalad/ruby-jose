module JOSE::JWA::Curve25519_Unsupported

  extend self

  def __ruby__?; true; end
  def __supported__?; false; end

  def ed25519_keypair(secret = nil)
    raise NotImplementedError
  end

  def ed25519_secret_to_public(sk)
    raise NotImplementedError
  end

  def ed25519_sign(m, sk)
    raise NotImplementedError
  end

  def ed25519_verify(sig, m, pk)
    raise NotImplementedError
  end

  def ed25519ph_keypair(secret = nil)
    raise NotImplementedError
  end

  def ed25519ph_secret_to_public(sk)
    raise NotImplementedError
  end

  def ed25519ph_sign(m, sk)
    raise NotImplementedError
  end

  def ed25519ph_verify(sig, m, pk)
    raise NotImplementedError
  end

  def x25519_keypair(secret = nil)
    raise NotImplementedError
  end

  def x25519_secret_to_public(sk)
    raise NotImplementedError
  end

  def x25519_shared_secret(pk, sk)
    raise NotImplementedError
  end

end
