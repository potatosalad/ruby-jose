module JOSE::JWA::X25519_RbNaCl

  extend self

  def curve25519(k, u)
    k = JOSE::JWA::X25519.coerce_scalar_bytes!(k) if not k.respond_to?(:bytesize)
    u = RbNaCl::GroupElements::Curve25519.new(JOSE::JWA::X25519.coerce_coordinate_bytes!(u)) if not u.is_a?(RbNaCl::GroupElements::Curve25519)
    return u.mult(k)
  end

  def x25519(sk, pk)
    return curve25519(sk, pk).to_bytes
  end

  def x25519_base(sk)
    sk = JOSE::JWA::X25519.coerce_scalar_bytes!(sk) if not sk.respond_to?(:bytesize)
    return RbNaCl::GroupElements::Curve25519.base_point.mult(sk).to_bytes
  end

  def keypair(sk = nil)
    sk ||= RbNaCl::Random.random_bytes(JOSE::JWA::X25519::C_bytes)
    sk = JOSE::JWA::X25519.clamp_scalar(sk)
    pk = sk_to_pk(sk)
    return pk, sk.to_bytes(JOSE::JWA::X25519::C_bits)
  end

  def shared_secret(pk, sk)
    return x25519(sk, pk)
  end

  def sk_to_pk(sk)
    return x25519_base(sk)
  end

end
