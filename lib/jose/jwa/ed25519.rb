module JOSE::JWA::Ed25519

  extend self

  C_bits = 256
  C_bytes = (C_bits + 7) / 8
  C_secretbytes = C_bytes
  C_publickeybytes = C_bytes
  C_secretkeybytes = C_secretbytes + C_publickeybytes
  C_signaturebytes = C_bytes + C_bytes
  C_B = JOSE::JWA::Edwards25519Point.stdbase.freeze

  def secret_to_curve25519(secret)
    raise ArgumentError, "secret must be #{C_secretbytes} bytes" if secret.bytesize != C_secretbytes
    curve25519_scalar = Digest::SHA512.digest(secret)[0, 32]
    curve25519_scalar.setbyte(0, curve25519_scalar.getbyte(0) & 248)
    curve25519_scalar.setbyte(31, (curve25519_scalar.getbyte(31) & 127) | 64)
    return curve25519_scalar
  end

  def secret_to_pk(secret)
    raise ArgumentError, "secret must be #{C_secretbytes} bytes" if secret.bytesize != C_secretbytes
    return (C_B * OpenSSL::BN.new(secret_to_curve25519(secret).reverse, 2).to_i).encode()
  end

  def keypair(secret = nil)
    secret ||= SecureRandom.random_bytes(C_secretbytes)
    pk = secret_to_pk(secret)
    sk = secret + pk
    return pk, sk
  end

  def sk_to_secret(sk)
    raise ArgumentError, "sk must be #{C_secretkeybytes} bytes" if sk.bytesize != C_secretkeybytes
    return sk[0, C_secretbytes]
  end

  def sk_to_pk(sk)
    raise ArgumentError, "sk must be #{C_secretkeybytes} bytes" if sk.bytesize != C_secretkeybytes
    return sk[C_secretbytes, C_secretkeybytes]
  end

  def sk_to_curve25519(sk)
    return secret_to_curve25519(sk_to_secret(sk))
  end

  def pk_to_curve25519(pk)
    raise ArgumentError, "pk must be #{C_publickeybytes} bytes" if pk.bytesize != C_publickeybytes
    a = C_B.decode(pk)
    u = (JOSE::JWA::X25519::C_F_one + a.y) / (JOSE::JWA::X25519::C_F_one - a.y)
    return u.to_bytes(C_bits)
  end

  def sign(m, sk)
    raise ArgumentError, "sk must be #{C_secretkeybytes} bytes" if sk.bytesize != C_secretkeybytes
    secret, pk = sk[0, 32], sk[32, 64]
    khash = Digest::SHA512.digest(secret)
    curve25519_scalar, seed = khash[0, 32], khash[32, 64]
    curve25519_scalar.setbyte(0, curve25519_scalar.getbyte(0) & 248)
    curve25519_scalar.setbyte(31, (curve25519_scalar.getbyte(31) & 127) | 64)
    a_s = OpenSSL::BN.new(curve25519_scalar.reverse, 2).to_i
    # Calculate r_s and r (r only used in encoded form)
    r_s = (OpenSSL::BN.new(Digest::SHA512.digest(seed+m).reverse, 2) % JOSE::JWA::Edwards25519Point::L).to_i
    r = (C_B * r_s).encode()
    # Calculate h.
    h = (OpenSSL::BN.new(Digest::SHA512.digest(r+pk+m).reverse, 2) % JOSE::JWA::Edwards25519Point::L).to_i
    # Calculate s.
    s = OpenSSL::BN.new((r_s+h*a_s) % JOSE::JWA::Edwards25519Point::L).to_s(2).rjust(C_bytes, JOSE::JWA::ZERO_PAD).reverse
    # The final signature is concatenation of r and s.
    return r+s
  end

  def sign_ph(m, sk)
    return sign(Digest::SHA512.digest(m), sk)
  end

  def verify(sig, m, pk)
    # Sanity-check sizes.
    return false if sig.bytesize != C_signaturebytes
    return false if pk.bytesize != C_publickeybytes
    # Split signature into R and S, and parse.
    r, s = sig[0, 32], sig[32, 64]
    r_p, s_s = C_B.decode(r), OpenSSL::BN.new(s.reverse, 2).to_i
    # Parse public key.
    a_p = C_B.decode(pk)
    # Check parse results.
    return false if r_p.nil? or a_p.nil? or s_s > JOSE::JWA::Edwards25519Point::L
    # Calculate h.
    h = (OpenSSL::BN.new(Digest::SHA512.digest(r+pk+m).reverse, 2) % JOSE::JWA::Edwards25519Point::L).to_i
    # Calculate left and right sides of check eq.
    rhs = r_p + (a_p * h)
    lhs = C_B * s_s
    JOSE::JWA::Edwards25519Point::C.times do
      lhs = lhs.double()
      rhs = rhs.double()
    end
    # Check eq. holds?
    return lhs == rhs
  end

  # def verify(sig, m, pk)
  #   return false if sig.bytesize != C_signaturebytes
  #   return false if pk.bytesize != C_publickeybytes
  #   r, s = sig[0, 32], sig[32, 64]
  #   a = C_B.decode(pk)
  #   k = (OpenSSL::BN.new(Digest::SHA512.digest(r+pk+m).reverse, 2) % JOSE::JWA::Edwards25519Point::L).to_i
  #   s_s = (OpenSSL::BN.new(s.reverse, 2)).to_i
  #   lhs = C_B * s_s
  #   rhs = C_B.decode(r) + (a * k)
  #   return lhs == rhs
  # end

  def verify_ph(sig, m, pk)
    return verify(sig, Digest::SHA512.digest(m), pk)
  end

  def coerce_publickey_bytes!(publickey)
    raise ArgumentError, "publickey size must be #{C_publickeybytes} bytes" if not valid_publickey?(publickey)
    publickey = publickey.to_bytes(C_bits) if publickey.is_a?(JOSE::JWA::FieldElement)
    publickey = publickey.to_bn if not publickey.is_a?(OpenSSL::BN) and publickey.respond_to?(:to_bn)
    publickey = publickey.to_s(2).rjust(C_bytes, JOSE::JWA::ZERO_PAD).reverse if publickey.is_a?(OpenSSL::BN)
    return publickey
  end

  def coerce_secret_bytes!(secret)
    raise ArgumentError, "secret size must be #{C_secretbytes} bytes" if not valid_secret?(secret)
    secret = secret.to_bytes(C_bits) if secret.is_a?(JOSE::JWA::FieldElement)
    secret = secret.to_bn if not secret.is_a?(OpenSSL::BN) and secret.respond_to?(:to_bn)
    secret = secret.to_s(2).rjust(C_bytes, JOSE::JWA::ZERO_PAD).reverse if secret.is_a?(OpenSSL::BN)
    return secret
  end

  def coerce_secretkey_bytes!(secretkey)
    raise ArgumentError, "secretkey size must be #{C_secretkeybytes} bytes" if not valid_secretkey?(secretkey)
    secretkey = secretkey.to_bytes(C_secretkeybytes * 8) if secretkey.is_a?(JOSE::JWA::FieldElement)
    secretkey = secretkey.to_bn if not secretkey.is_a?(OpenSSL::BN) and secretkey.respond_to?(:to_bn)
    secretkey = secretkey.to_s(2).rjust(C_secretkeybytes, JOSE::JWA::ZERO_PAD).reverse if secretkey.is_a?(OpenSSL::BN)
    return secretkey
  end

  def valid_publickey?(publickey)
    return true if publickey.is_a?(JOSE::JWA::FieldElement) and publickey.p == C_p
    if not publickey.is_a?(OpenSSL::BN) and publickey.respond_to?(:to_bn)
      publickey = publickey.to_bn
    end
    pkbytes = 0
    if publickey.is_a?(OpenSSL::BN)
      if publickey.num_bytes > C_publickeybytes
        pkbytes = publickey.num_bytes
      else
        pkbytes = C_publickeybytes
      end
    end
    pkbytes = publickey.bytesize if publickey.respond_to?(:bytesize)
    return !!(pkbytes == C_publickeybytes)
  end

  def valid_secret?(secret)
    return true if secret.is_a?(JOSE::JWA::FieldElement) and secret.p == C_p
    if not secret.is_a?(OpenSSL::BN) and secret.respond_to?(:to_bn)
      secret = secret.to_bn
    end
    seedbytes = 0
    if secret.is_a?(OpenSSL::BN)
      if secret.num_bytes > C_secretbytes
        seedbytes = secret.num_bytes
      else
        seedbytes = C_secretbytes
      end
    end
    seedbytes = secret.bytesize if secret.respond_to?(:bytesize)
    return !!(seedbytes == C_secretbytes)
  end

  def valid_secretkey?(secretkey)
    return true if secretkey.is_a?(JOSE::JWA::FieldElement) and secretkey.p == C_p
    if not secretkey.is_a?(OpenSSL::BN) and secretkey.respond_to?(:to_bn)
      secretkey = secretkey.to_bn
    end
    skbytes = 0
    if secretkey.is_a?(OpenSSL::BN)
      if secretkey.num_bytes > C_secretkeybytes
        skbytes = secretkey.num_bytes
      else
        skbytes = C_secretkeybytes
      end
    end
    skbytes = secretkey.bytesize if secretkey.respond_to?(:bytesize)
    return !!(skbytes == C_secretkeybytes)
  end

end
