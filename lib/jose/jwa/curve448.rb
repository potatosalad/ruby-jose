module JOSE::JWA::Curve448

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

  def ed448_keypair(secret = nil)
    return (@__implementation__ || __implementation__).ed448_keypair(secret)
  end

  def ed448_secret_to_public(sk)
    return (@__implementation__ || __implementation__).ed448_secret_to_public(sk)
  end

  def ed448_sign(m, sk)
    return (@__implementation__ || __implementation__).ed448_sign(m, sk)
  end

  def ed448_verify(sig, m, pk)
    return (@__implementation__ || __implementation__).ed448_verify(sig, m, pk)
  end

  def ed448ph_keypair(secret = nil)
    return (@__implementation__ || __implementation__).ed448ph_keypair(secret)
  end

  def ed448ph_secret_to_public(sk)
    return (@__implementation__ || __implementation__).ed448ph_secret_to_public(sk)
  end

  def ed448ph_sign(m, sk)
    return (@__implementation__ || __implementation__).ed448ph_sign(m, sk)
  end

  def ed448ph_verify(sig, m, pk)
    return (@__implementation__ || __implementation__).ed448ph_verify(sig, m, pk)
  end

  def x448_keypair(secret = nil)
    return (@__implementation__ || __implementation__).x448_keypair(secret)
  end

  def x448_secret_to_public(sk)
    return (@__implementation__ || __implementation__).x448_secret_to_public(sk)
  end

  def x448_shared_secret(pk, sk)
    return (@__implementation__ || __implementation__).x448_shared_secret(pk, sk)
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
    implementation ||= JOSE::JWA::Curve448_Unsupported
    return implementation
  end

end

require 'jose/jwa/ed448'
require 'jose/jwa/x448'

require 'jose/jwa/curve448_unsupported'
require 'jose/jwa/curve448_ruby'
