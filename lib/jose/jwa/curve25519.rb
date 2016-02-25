module JOSE::JWA::Curve25519

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
    @__implementation__ = __pick_best_implementation__ if @__implementation__.nil? or @__implementation__.__ruby__? or not @__implementation__.__supported__?
    MUTEX.unlock if lock
  end

  def ed25519_keypair(secret = nil)
    return (@__implementation__ || __implementation__).ed25519_keypair(secret)
  end

  def ed25519_secret_to_public(sk)
    return (@__implementation__ || __implementation__).ed25519_secret_to_public(sk)
  end

  def ed25519_sign(m, sk)
    return (@__implementation__ || __implementation__).ed25519_sign(m, sk)
  end

  def ed25519_verify(sig, m, pk)
    return (@__implementation__ || __implementation__).ed25519_verify(sig, m, pk)
  end

  def ed25519ph_keypair(secret = nil)
    return (@__implementation__ || __implementation__).ed25519ph_keypair(secret)
  end

  def ed25519ph_secret_to_public(sk)
    return (@__implementation__ || __implementation__).ed25519ph_secret_to_public(sk)
  end

  def ed25519ph_sign(m, sk)
    return (@__implementation__ || __implementation__).ed25519ph_sign(m, sk)
  end

  def ed25519ph_verify(sig, m, pk)
    return (@__implementation__ || __implementation__).ed25519ph_verify(sig, m, pk)
  end

  def x25519_keypair(secret = nil)
    return (@__implementation__ || __implementation__).x25519_keypair(secret)
  end

  def x25519_secret_to_public(sk)
    return (@__implementation__ || __implementation__).x25519_secret_to_public(sk)
  end

  def x25519_shared_secret(pk, sk)
    return (@__implementation__ || __implementation__).x25519_shared_secret(pk, sk)
  end

private
  def __pick_best_implementation__
    implementation = nil
    implementation = @__implementations__.detect do |implementation|
      next implementation.__supported__?
    end
    implementation ||= @__ruby_implementations__.detect do |implementation|
      next implementation.__supported__?
    end
    implementation ||= JOSE::JWA::Curve25519_Unsupported
    return implementation
  end

end

require 'jose/jwa/ed25519'
require 'jose/jwa/ed25519_rbnacl'
require 'jose/jwa/x25519'
require 'jose/jwa/x25519_rbnacl'

require 'jose/jwa/curve25519_unsupported'
require 'jose/jwa/curve25519_ruby'
require 'jose/jwa/curve25519_rbnacl'
