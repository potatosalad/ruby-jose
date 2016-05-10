module JOSE::JWA::Curve25519_RbNaCl

  extend self

  def __ruby__?; false; end

  def __supported__?
    return @supported ||= begin
      begin
        require 'rbnacl/libsodium'
      rescue LoadError
      end
      begin
        require 'rbnacl'
      rescue LoadError
      end
      !!(defined?(RbNaCl::GroupElements::Curve25519))
    end
  end

  def ed25519_keypair(secret = nil)
    return JOSE::JWA::Ed25519_RbNaCl.keypair(secret)
  end

  def ed25519_secret_to_public(sk)
    return JOSE::JWA::Ed25519_RbNaCl.sk_to_pk(sk)
  end

  def ed25519_sign(m, sk)
    return JOSE::JWA::Ed25519_RbNaCl.sign(m, sk)
  end

  def ed25519_verify(sig, m, pk)
    return JOSE::JWA::Ed25519_RbNaCl.verify(sig, m, pk)
  end

  def ed25519ph_keypair(secret = nil)
    return JOSE::JWA::Ed25519_RbNaCl.keypair(secret)
  end

  def ed25519ph_secret_to_public(sk)
    return JOSE::JWA::Ed25519_RbNaCl.sk_to_pk(sk)
  end

  def ed25519ph_sign(m, sk)
    return JOSE::JWA::Ed25519_RbNaCl.sign_ph(m, sk)
  end

  def ed25519ph_verify(sig, m, pk)
    return JOSE::JWA::Ed25519_RbNaCl.verify_ph(sig, m, pk)
  end

  def x25519_keypair(secret = nil)
    return JOSE::JWA::X25519_RbNaCl.keypair(secret)
  end

  def x25519_secret_to_public(sk)
    return JOSE::JWA::X25519_RbNaCl.sk_to_pk(sk)
  end

  def x25519_shared_secret(pk, sk)
    return JOSE::JWA::X25519_RbNaCl.shared_secret(pk, sk)
  end

end

JOSE::JWA::Curve25519.__register__(JOSE::JWA::Curve25519_RbNaCl)
