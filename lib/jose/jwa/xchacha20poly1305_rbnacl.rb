module JOSE::JWA::XChaCha20Poly1305_RbNaCl

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
      !!(defined?(RbNaCl::AEAD::XChaCha20Poly1305IETF))
    end
  end

  def xchacha20poly1305_aead_encrypt(key, nonce, aad, plaintext)
    cipher = RbNaCl::AEAD::XChaCha20Poly1305IETF.new(key)
    ciphertext_with_tag = cipher.encrypt(nonce, plaintext, aad)
    return [ciphertext_with_tag[0..-17], ciphertext_with_tag[-16..-1]]
  end

  def xchacha20poly1305_aead_decrypt(key, nonce, aad, ciphertext, tag)
    cipher = RbNaCl::AEAD::XChaCha20Poly1305IETF.new(key)
    ciphertext_with_tag = [ciphertext, tag].join()
    return cipher.decrypt(nonce, ciphertext_with_tag, aad)
  end

end

JOSE::JWA::XChaCha20Poly1305.__register__(JOSE::JWA::XChaCha20Poly1305_RbNaCl)
