module JOSE::JWA::X25519_CryptoRb

  extend self

  def curve25519(k, u)
    k = coerce_scalar!(k)
    u = coerce_montgomery_u!(u)
    return k.diffie_hellman(u)
  end

  def x25519(sk, pk)
    return curve25519(sk, pk).to_bytes()
  end

  def x25519_base(sk)
    scalar = coerce_scalar!(sk)
    return scalar.public_key.to_bytes()
  end

  def keypair(sk = nil)
    sk ||= X25519::Scalar.generate()
    scalar = coerce_scalar!(sk)
    pk = sk_to_pk(scalar)
    return pk, scalar.to_bytes()
  end

  def shared_secret(pk, sk)
    return x25519(sk, pk)
  end

  def sk_to_pk(sk)
    return x25519_base(sk)
  end

  def coerce_montgomery_u!(pk)
    return pk if pk.is_a?(X25519::MontgomeryU)
    pk = JOSE::JWA::X25519.coerce_coordinate_bytes!(u) if not pk.respond_to?(:bytesize)
    return X25519::MontgomeryU.new(pk)
  end

  def coerce_scalar!(sk)
    return sk if sk.is_a?(X25519::Scalar)
    sk = JOSE::JWA::X25519.coerce_scalar_bytes!(sk) if not sk.respond_to?(:bytesize)
    return X25519::Scalar.new(sk)
  end

end
