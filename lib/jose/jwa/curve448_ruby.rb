module JOSE::JWA::Curve448_Ruby

  extend self

  def __ruby__?; true; end
  def __supported__?; JOSE.__crypto_fallback__; end

  def ed448_keypair(secret = nil)
    return JOSE::JWA::Ed448.keypair(secret)
  end

  def ed448_secret_to_public(sk)
    return JOSE::JWA::Ed448.sk_to_pk(sk)
  end

  def ed448_sign(m, sk)
    return JOSE::JWA::Ed448.sign(m, sk)
  end

  def ed448_verify(sig, m, pk)
    return JOSE::JWA::Ed448.verify(sig, m, pk)
  end

  def ed448ph_keypair(secret = nil)
    return JOSE::JWA::Ed448.keypair(secret)
  end

  def ed448ph_secret_to_public(sk)
    return JOSE::JWA::Ed448.sk_to_pk(sk)
  end

  def ed448ph_sign(m, sk)
    return JOSE::JWA::Ed448.sign_ph(m, sk)
  end

  def ed448ph_verify(sig, m, pk)
    return JOSE::JWA::Ed448.verify_ph(sig, m, pk)
  end

  def x448_keypair(secret = nil)
    return JOSE::JWA::X448.keypair(secret)
  end

  def x448_secret_to_public(sk)
    return JOSE::JWA::X448.sk_to_pk(sk)
  end

  def x448_shared_secret(pk, sk)
    return JOSE::JWA::X448.shared_secret(pk, sk)
  end

end

JOSE::JWA::Curve448.__register__(JOSE::JWA::Curve448_Ruby, true)
