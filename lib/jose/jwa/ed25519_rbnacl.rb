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
    verify_key = RbNaCl::Signatures::Ed25519::VerifyKey.new(pk)
    if m.respond_to?(:bytesize) and m.bytesize == 0
      # RbNaCl does not allow empty message signatures.
      key = verify_key.instance_variable_get(:@key)
      signature = sig.to_str
      signature_bytes = verify_key.signature_bytes
      RbNaCl::Util.check_length(signature, signature_bytes, "signature")
      signed_message = signature + m
      raise RbNaCl::LengthError, "Signed message can not be nil" if signed_message.nil?
      raise RbNaCl::LengthError, "Signed message can not be shorter than a signature" if signed_message.bytesize < signature_bytes
      buffer = RbNaCl::Util.zeros(signed_message.bytesize)
      buffer_len = RbNaCl::Util.zeros(FFI::Type::LONG_LONG.size)
      success = verify_key.class.sign_ed25519_open(buffer, buffer_len, signed_message, signed_message.bytesize, key)
      raise(RbNaCl::BadSignatureError, "signature was forged/corrupt") unless success
      return true
    else
      return verify_key.verify(sig, m)
    end
  end

  def verify_ph(sig, m, pk)
    return verify(sig, RbNaCl::Hash.sha512(m), pk)
  end

end
