module JOSE::JWA::XChaCha20Poly1305_Unsupported

  extend self

  def __ruby__?; true; end
  def __supported__?; false; end

  def xchacha20poly1305_aead_encrypt(key, nonce, aad, plaintext)
    raise NotImplementedError
  end

  def xchacha20poly1305_aead_decrypt(key, nonce, aad, ciphertext, tag)
    raise NotImplementedError
  end

end
