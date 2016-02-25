module JOSE::JWA::Ed25519_RbNaCl

  extend self

  def keypair(secret = nil)
    secret ||= RbNaCl::Random.random_bytes(RbNaCl::Signatures::Ed25519::SEEDBYTES)
    RbNaCl::Util.check_length(secret, RbNaCl::Signatures::Ed25519::SEEDBYTES, "secret")
    pk = RbNaCl::Util.zeros(RbNaCl::Signatures::Ed25519::VERIFYKEYBYTES)
    sk = RbNaCl::Util.zeros(RbNaCl::Signatures::Ed25519::SIGNINGKEYBYTES)
    RbNaCl::Signatures::Ed25519::SigningKey.sign_ed25519_seed_keypair(pk, sk, secret) || fail(RbNaCl::CryptoError, "Failed to generate a key pair")
    return pk, sk
  end

  def sk_to_pk(sk)
    return sk[RbNaCl::Signatures::Ed25519::VERIFYKEYBYTES..-1]
  end

  def sign(m, sk)
    signing_key = RbNaCl::Signatures::Ed25519::SigningKey.allocate
    signing_key.instance_variable_set(:@signing_key, sk)
    return signing_key.sign(m)
  end

  def sign_ph(m, sk)
    return sign(RbNaCl::Hash.sha512(m), sk)
  end

  def verify(sig, m, pk)
    return RbNaCl::Signatures::Ed25519::VerifyKey.new(pk).verify(sig, m)
  end

  def verify_ph(sig, m, pk)
    return verify(sig, RbNaCl::Hash.sha512(m), pk)
  end

end
