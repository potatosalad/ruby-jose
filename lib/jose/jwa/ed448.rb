module JOSE::JWA::Ed448

  extend self

  C_bits = 456
  C_bytes = (C_bits + 7) / 8
  C_secretbytes = C_bytes
  C_publickeybytes = C_bytes
  C_secretkeybytes = C_secretbytes + C_publickeybytes
  C_signaturebytes = C_bytes + C_bytes
  C_B = JOSE::JWA::Edwards448Point.stdbase.freeze

  def secret_to_curve448(secret)
    raise ArgumentError, "secret must be #{C_secretbytes} bytes" if secret.bytesize != C_secretbytes
    curve448_scalar = JOSE::JWA::SHA3.shake256(secret, 114)[0, 56]
    curve448_scalar.setbyte(0, curve448_scalar.getbyte(0) & 252)
    curve448_scalar.setbyte(55, curve448_scalar.getbyte(55) | 128)
    return curve448_scalar
  end

  def secret_to_pk(secret)
    raise ArgumentError, "secret must be #{C_secretbytes} bytes" if secret.bytesize != C_secretbytes
    return (C_B * OpenSSL::BN.new(secret_to_curve448(secret).reverse, 2).to_i).encode()
  end

  def keypair(secret = nil)
    secret ||= SecureRandom.random_bytes(C_secretbytes)
    pk = secret_to_pk(secret)
    sk = secret + pk
    return pk, sk
  end

  def sk_to_secret(sk)
    return sk[0, C_secretbytes] if sk.bytesize == C_secretkeybytes
    raise ArgumentError, "sk must be #{C_secretkeybytes} bytes"
  end

  def sk_to_pk(sk)
    return sk[C_secretbytes, C_secretkeybytes] if sk.bytesize == C_secretkeybytes
    raise ArgumentError, "sk must be #{C_secretkeybytes} bytes"
  end

  def sk_to_curve448(sk)
    return secret_to_curve448(sk_to_secret(sk))
  end

  def pk_to_curve448(pk)
    raise ArgumentError, "pk must be #{C_publickeybytes} bytes" if pk.bytesize != C_publickeybytes
    a = C_B.decode(pk)
    u = a.y.sqr / a.x.sqr
    return u.to_bytes(448)
  end

  def sign(m, sk, ctx = nil)
    raise ArgumentError, "sk must be #{C_secretkeybytes} bytes" if sk.bytesize != C_secretkeybytes
    ctx ||= ''
    raise ArgumentError, "ctx must be 255 bytes or smaller" if ctx.bytesize > 255
    secret, pk = nil, nil
    if sk.bytesize == C_secretkeybytes
      secret, pk = sk[0, 57], sk[57, 114]
    end
    khash = JOSE::JWA::SHA3.shake256(secret, 114)
    curve448_scalar, seed = khash[0, 57], khash[57, 114]
    curve448_scalar.setbyte(0, curve448_scalar.getbyte(0) & 252)
    curve448_scalar.setbyte(55, curve448_scalar.getbyte(55) | 128)
    curve448_scalar.setbyte(56, 0)
    a_s = OpenSSL::BN.new(curve448_scalar.reverse, 2).to_i
    # Calculate r_s and r (r only used in encoded form)
    r_s = (OpenSSL::BN.new(JOSE::JWA::SHA3.shake256(['SigEd448', 0, ctx.bytesize, ctx, seed, m].pack('a*CCa*a*a*'), 114).reverse, 2) % JOSE::JWA::Edwards448Point::L).to_i
    r = (C_B * r_s).encode()
    # Calculate h.
    h = (OpenSSL::BN.new(JOSE::JWA::SHA3.shake256(['SigEd448', 0, ctx.bytesize, ctx, r, pk, m].pack('a*CCa*a*a*a*'), 114).reverse, 2) % JOSE::JWA::Edwards448Point::L).to_i
    # Calculate s.
    s = OpenSSL::BN.new((r_s+h*a_s) % JOSE::JWA::Edwards448Point::L).to_s(2).rjust(C_bytes, JOSE::JWA::ZERO_PAD).reverse
    # The final signature is concatenation of r and s.
    return r+s
  end

  def sign_ph(m, sk, ctx = nil)
    raise ArgumentError, "sk must be #{C_secretkeybytes} bytes" if sk.bytesize != C_secretkeybytes
    ctx ||= ''
    raise ArgumentError, "ctx must be 255 bytes or smaller" if ctx.bytesize > 255
    m = JOSE::JWA::SHA3.shake256(['SigEd448', 2, ctx.bytesize, ctx, m].pack('a*CCa*a*'), 64)
    secret, pk = nil, nil
    if sk.bytesize == C_secretkeybytes
      secret, pk = sk[0, 57], sk[57, 114]
    end
    khash = JOSE::JWA::SHA3.shake256(secret, 114)
    curve448_scalar, seed = khash[0, 57], khash[57, 114]
    curve448_scalar.setbyte(0, curve448_scalar.getbyte(0) & 252)
    curve448_scalar.setbyte(55, curve448_scalar.getbyte(55) | 128)
    curve448_scalar.setbyte(56, 0)
    a_s = OpenSSL::BN.new(curve448_scalar.reverse, 2).to_i
    # Calculate r_s and r (r only used in encoded form)
    r_s = (OpenSSL::BN.new(JOSE::JWA::SHA3.shake256(['SigEd448', 1, ctx.bytesize, ctx, seed, m].pack('a*CCa*a*a*'), 114).reverse, 2) % JOSE::JWA::Edwards448Point::L).to_i
    r = (C_B * r_s).encode()
    # Calculate h.
    h = (OpenSSL::BN.new(JOSE::JWA::SHA3.shake256(['SigEd448', 1, ctx.bytesize, ctx, r, pk, m].pack('a*CCa*a*a*a*'), 114).reverse, 2) % JOSE::JWA::Edwards448Point::L).to_i
    # Calculate s.
    s = OpenSSL::BN.new((r_s+h*a_s) % JOSE::JWA::Edwards448Point::L).to_s(2).rjust(C_bytes, JOSE::JWA::ZERO_PAD).reverse
    # The final signature is concatenation of r and s.
    return r+s
  end

  def verify(sig, m, pk, ctx = nil)
    ctx ||= ''
    raise ArgumentError, "ctx must be 255 bytes or smaller" if ctx.bytesize > 255
    # Sanity-check sizes.
    return false if sig.bytesize != C_signaturebytes
    return false if pk.bytesize != C_publickeybytes
    # Split signature into R and S, and parse.
    r, s = sig[0, 57], sig[57, 114]
    r_p, s_s = C_B.decode(r), OpenSSL::BN.new(s.reverse, 2).to_i
    # Parse public key.
    a_p = C_B.decode(pk)
    # Check parse results.
    return false if r_p.nil? or a_p.nil? or s_s > JOSE::JWA::Edwards448Point::L
    # Calculate h.
    h = (OpenSSL::BN.new(JOSE::JWA::SHA3.shake256(['SigEd448', 0, ctx.bytesize, ctx, r, pk, m].pack('a*CCa*a*a*a*'), 114).reverse, 2) % JOSE::JWA::Edwards448Point::L).to_i
    # Calculate left and right sides of check eq.
    rhs = r_p + (a_p * h)
    lhs = C_B * s_s
    JOSE::JWA::Edwards448Point::C.times do
      lhs = lhs.double()
      rhs = rhs.double()
    end
    # Check eq. holds?
    return lhs == rhs
  end

  def verify_ph(sig, m, pk, ctx = nil)
    ctx ||= ''
    raise ArgumentError, "ctx must be 255 bytes or smaller" if ctx.bytesize > 255
    m = JOSE::JWA::SHA3.shake256(['SigEd448', 2, ctx.bytesize, ctx, m].pack('a*CCa*a*'), 64)
    # Sanity-check sizes.
    return false if sig.bytesize != C_signaturebytes
    return false if pk.bytesize != C_publickeybytes
    # Split signature into R and S, and parse.
    r, s = sig[0, 57], sig[57, 114]
    r_p, s_s = C_B.decode(r), OpenSSL::BN.new(s.reverse, 2).to_i
    # Parse public key.
    a_p = C_B.decode(pk)
    # Check parse results.
    return false if r_p.nil? or a_p.nil? or s_s > JOSE::JWA::Edwards448Point::L
    # Calculate h.
    h = (OpenSSL::BN.new(JOSE::JWA::SHA3.shake256(['SigEd448', 1, ctx.bytesize, ctx, r, pk, m].pack('a*CCa*a*a*a*'), 114).reverse, 2) % JOSE::JWA::Edwards448Point::L).to_i
    # Calculate left and right sides of check eq.
    rhs = r_p + (a_p * h)
    lhs = C_B * s_s
    JOSE::JWA::Edwards448Point::C.times do
      lhs = lhs.double()
      rhs = rhs.double()
    end
    # Check eq. holds?
    return lhs == rhs
  end

end
