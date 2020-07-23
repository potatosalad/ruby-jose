module JOSE::JWA::XChaCha20Poly1305

  extend self

  MUTEX = Mutex.new

  @__implementations__ = []
  @__ruby_implementations__ = []

  def __implementation__
    return MUTEX.synchronize { @__implementation__ ||= __pick_best_implementation__ }
  end

  def __implementation__=(implementation)
    return MUTEX.synchronize { @__implementation__ = implementation }
  end

  def __register__(implementation, ruby = false)
    MUTEX.synchronize {
      if ruby
        @__ruby_implementations__.unshift(implementation)
      else
        @__implementations__.unshift(implementation)
      end
      __config_change__(false)
      implementation
    }
  end

  def __config_change__(lock = true)
    MUTEX.lock if lock
    @__implementation__ ||= nil
    @__implementation__ = __pick_best_implementation__ if @__implementation__.nil? or @__implementation__.__ruby__? or not @__implementation__.__supported__?
    MUTEX.unlock if lock
  end

  def xchacha20poly1305_aead_encrypt(key, nonce, aad, plaintext)
    return (@__implementation__ || __implementation__).xchacha20poly1305_aead_encrypt(key, nonce, aad, plaintext)
  end

  def xchacha20poly1305_aead_decrypt(key, nonce, aad, ciphertext, tag)
    return (@__implementation__ || __implementation__).xchacha20poly1305_aead_decrypt(key, nonce, aad, ciphertext, tag)
  end

private
  def __pick_best_implementation__
    implementation = nil
    implementation = @__implementations__.detect do |mod|
      next mod.__supported__?
    end
    implementation ||= @__ruby_implementations__.detect do |mod|
      next mod.__supported__?
    end
    implementation ||= JOSE::JWA::XChaCha20Poly1305_Unsupported
    return implementation
  end

end

require 'jose/jwa/xchacha20poly1305_unsupported'
require 'jose/jwa/xchacha20poly1305_rbnacl'
