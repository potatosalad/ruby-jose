module JOSE::JWA::Ed25519_CryptoRb

  extend self

  def keypair(secret = nil)
    secret ||= Ed25519::SigningKey.generate()
    sk = coerce_signing_key!(secret)
    pk = sk.verify_key()
    return pk.to_bytes(), sk.keypair()
  end

  def sk_to_pk(sk)
    return sk[Ed25519::KEY_SIZE..-1]
  end

  def sign(m, sk)
    signing_key = coerce_signing_key!(sk)
    return signing_key.sign(m)
  end

  def sign_ph(m, sk)
    return sign(Digest::SHA512.digest(m), sk)
  end

  def verify(sig, m, pk)
    return Ed25519::VerifyKey.new(pk).verify(sig, m)
  end

  def verify_ph(sig, m, pk)
    return verify(sig, Digest::SHA512.digest(m), pk)
  end

  def coerce_signing_key!(sk)
    return sk if sk.is_a?(Ed25519::SigningKey)
    sk =
      if not sk.respond_to?(:bytesize)
        begin
          JOSE::JWA::Ed25519.coerce_secret_bytes!(sk)
        rescue ArgumentError
          JOSE::JWA::Ed25519.coerce_secretkey_bytes!(sk)
        end
      else
        sk
      end
    return Ed25519::SigningKey.from_keypair(sk) if sk.bytesize === JOSE::JWA::Ed25519::C_secretkeybytes
    return Ed25519::SigningKey.new(sk)
  end

  def coerce_verify_key!(pk)
    return pk if pk.is_a?(Ed25519::VerifyKey)
    pk = JOSE::JWA::Ed25519.coerce_publickey_bytes!(pk) if not pk.respond_to?(:bytesize)
    return Ed25519::VerifyKey.new(pk)
  end

end
