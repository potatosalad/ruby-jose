module JOSE::JWA::Curve25519_Ruby

  extend self

  def __ruby__?; true; end
  def __supported__?; JOSE.crypto_fallback; end

  def ed25519_keypair(secret = nil)
    return JOSE::JWA::Ed25519.keypair(secret)
  end

  def ed25519_secret_to_public(sk)
    return JOSE::JWA::Ed25519.sk_to_pk(sk)
  end

  def ed25519_sign(m, sk)
    return JOSE::JWA::Ed25519.sign(m, sk)
  end

  def ed25519_verify(sig, m, pk)
    return JOSE::JWA::Ed25519.verify(sig, m, pk)
  end

  def ed25519ph_keypair(secret = nil)
    return JOSE::JWA::Ed25519.keypair(secret)
  end

  def ed25519ph_secret_to_public(sk)
    return JOSE::JWA::Ed25519.sk_to_pk(sk)
  end

  def ed25519ph_sign(m, sk)
    return JOSE::JWA::Ed25519.sign_ph(m, sk)
  end

  def ed25519ph_verify(sig, m, pk)
    return JOSE::JWA::Ed25519.verify_ph(sig, m, pk)
  end

  def x25519_keypair(secret = nil)
    return JOSE::JWA::X25519.keypair(secret)
  end

  def x25519_secret_to_public(sk)
    return JOSE::JWA::X25519.sk_to_pk(sk)
  end

  def x25519_shared_secret(pk, sk)
    return JOSE::JWA::X25519.shared_secret(pk, sk)
  end

end

JOSE::JWA::Curve25519.__register__(JOSE::JWA::Curve25519_Ruby, true)
