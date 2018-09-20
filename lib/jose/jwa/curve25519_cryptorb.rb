module JOSE::JWA::Curve25519_CryptoRb

  extend self

  def __ruby__?; false; end

  def __supported__?
    return @supported ||= begin
      begin
        require 'ed25519'
      rescue LoadError
      end
      begin
        require 'x25519'
      rescue LoadError
      end
      !!(defined?(Ed25519::SigningKey) and defined?(X25519::Scalar))
    end
  end

  def ed25519_keypair(secret = nil)
    return JOSE::JWA::Ed25519_CryptoRb.keypair(secret)
  end

  def ed25519_secret_to_public(sk)
    return JOSE::JWA::Ed25519_CryptoRb.sk_to_pk(sk)
  end

  def ed25519_sign(m, sk)
    return JOSE::JWA::Ed25519_CryptoRb.sign(m, sk)
  end

  def ed25519_verify(sig, m, pk)
    return JOSE::JWA::Ed25519_CryptoRb.verify(sig, m, pk)
  end

  def ed25519ph_keypair(secret = nil)
    return JOSE::JWA::Ed25519_CryptoRb.keypair(secret)
  end

  def ed25519ph_secret_to_public(sk)
    return JOSE::JWA::Ed25519_CryptoRb.sk_to_pk(sk)
  end

  def ed25519ph_sign(m, sk)
    return JOSE::JWA::Ed25519_CryptoRb.sign_ph(m, sk)
  end

  def ed25519ph_verify(sig, m, pk)
    return JOSE::JWA::Ed25519_CryptoRb.verify_ph(sig, m, pk)
  end

  def x25519_keypair(secret = nil)
    return JOSE::JWA::X25519_CryptoRb.keypair(secret)
  end

  def x25519_secret_to_public(sk)
    return JOSE::JWA::X25519_CryptoRb.sk_to_pk(sk)
  end

  def x25519_shared_secret(pk, sk)
    return JOSE::JWA::X25519_CryptoRb.shared_secret(pk, sk)
  end

end

JOSE::JWA::Curve25519.__register__(JOSE::JWA::Curve25519_CryptoRb)
