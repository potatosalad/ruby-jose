require 'jose/version'

require 'base64'
require 'immutable/hash'
require 'json'
require 'openssl'
require 'securerandom'
require 'thread'
require 'zlib'

# JOSE stands for JSON Object Signing and Encryption which is a is a set of
# standards established by the [JOSE Working Group](https://datatracker.ietf.org/wg/jose).
#
# JOSE is split into 5 main components:
#
#   * {JOSE::JWA JOSE::JWA} - JSON Web Algorithms (JWA) {https://tools.ietf.org/html/rfc7518 RFC 7518}
#   * {JOSE::JWE JOSE::JWE} - JSON Web Encryption (JWE) {https://tools.ietf.org/html/rfc7516 RFC 7516}
#   * {JOSE::JWK JOSE::JWK} - JSON Web Key (JWK)        {https://tools.ietf.org/html/rfc7517 RFC 7517}
#   * {JOSE::JWS JOSE::JWS} - JSON Web Signature (JWS)  {https://tools.ietf.org/html/rfc7515 RFC 7515}
#   * {JOSE::JWT JOSE::JWT} - JSON Web Token (JWT)      {https://tools.ietf.org/html/rfc7519 RFC 7519}
#
# Additional specifications and drafts implemented:
#
#   * JSON Web Key (JWK) Thumbprint [RFC 7638](https://tools.ietf.org/html/rfc7638)
#   * JWS Unencoded Payload Option  [draft-ietf-jose-jws-signing-input-options-04](https://tools.ietf.org/html/draft-ietf-jose-jws-signing-input-options-04)
module JOSE

  # @!visibility private
  MUTEX = Mutex.new

  # Immutable Map structure based on `Immutable::Hash`.
  class Map < Immutable::Hash; end

  @__crypto_fallback__ = ENV['JOSE_CRYPTO_FALLBACK'] ? true : false
  @__unsecured_signing__ = ENV['JOSE_UNSECURED_SIGNING'] ? true : false

  # Gets the current Cryptographic Algorithm Fallback state, defaults to `false`.
  # @return [Boolean]
  def self.crypto_fallback
    return @__crypto_fallback__
  end

  # Sets the current Cryptographic Algorithm Fallback state.
  # @param [Boolean] boolean
  # @return [Boolean]
  def self.crypto_fallback=(boolean)
    boolean = !!boolean
    MUTEX.synchronize {
      @__crypto_fallback__ = boolean
      __config_change__
    }
    return boolean
  end

  # Gets the current Curve25519 module used by {JOSE::JWA::Curve25519 JOSE::JWA::Curve25519}, see {.curve25519_module=} for default.
  # @return [Module]
  def self.curve25519_module
    return JOSE::JWA::Curve25519.__implementation__
  end

  # Sets the current Curve25519 module used by {JOSE::JWA::Curve25519 JOSE::JWA::Curve25519}.
  #
  # Currently supported Curve25519 modules (first found is used as default):
  #
  #   * {https://github.com/cryptosphere/rbnacl `RbNaCl`}
  #   * {JOSE::JWA::Curve25519_Ruby JOSE::JWA::Curve25519_Ruby} - only supported when {.crypto_fallback} is `true`
  #
  # Additional modules that implement the functions specified in {JOSE::JWA::Curve25519 JOSE::JWA::Curve25519} may also be used.
  # @param [Module] mod
  # @return [Module]
  def self.curve25519_module=(mod)
    JOSE::JWA::Curve25519.__implementation__ = mod
  end

  # Gets the current Curve448 module used by {JOSE::JWA::Curve448 JOSE::JWA::Curve448}, see {.curve25519_module=} for default.
  # @return [Module]
  def self.curve448_module
    return JOSE::JWA::Curve448.__implementation__
  end

  # Sets the current Curve448 module used by {JOSE::JWA::Curve448 JOSE::JWA::Curve448}.
  #
  # Currently supported Curve448 modules (first found is used as default):
  #
  #   * {JOSE::JWA::Curve448_Ruby JOSE::JWA::Curve448_Ruby} - only supported when {.crypto_fallback} is `true`
  #
  # Additional modules that implement the functions specified in {JOSE::JWA::Curve448 JOSE::JWA::Curve448} may also be used.
  # @param [Module] mod
  # @return [Module]
  def self.curve448_module=(mod)
    JOSE::JWA::Curve448.__implementation__ = mod
  end

  # Decode JSON binary to a term.
  # @param [String] binary
  # @return [Object]
  def self.decode(binary)
    return JSON.load(binary)
  end

  # Encode a term to JSON binary and sorts `Hash` and {JOSE::Map JOSE::Map} keys.
  # @param [Object] term
  # @return [Object]
  def self.encode(term)
    return JSON.dump(sort_maps(term))
  end

  # Gets the current Unsecured Signing state, defaults to `false`.
  # @return [Boolean]
  def self.unsecured_signing
    return @__unsecured_signing__
  end

  # Sets the current Unsecured Signing state.
  #
  # Enables/disables the `"none"` algorithm used for signing and verifying.
  #
  # See {https://auth0.com/blog/2015/03/31/critical-vulnerabilities-in-json-web-token-libraries/ Critical vulnerabilities in JSON Web Token libraries} for more information.
  # @param [Boolean] boolean
  # @return [Boolean]
  def self.unsecured_signing=(boolean)
    boolean = !!boolean
    MUTEX.synchronize {
      @__unsecured_signing__ = boolean
      __config_change__
    }
    return boolean
  end

  # Returns the Base64Url decoded version of `binary` without padding.
  # @param [String] binary
  # @return [String]
  def self.urlsafe_decode64(binary)
    binary = binary.tr('-_', '+/')
    case binary.bytesize % 4
    when 2
      binary += '=='
    when 3
      binary += '='
    end
    return Base64.decode64(binary)
  end

  # Returns the Base64Url encoded version of `binary` without padding.
  # @param [String] binary
  # @return [String]
  def self.urlsafe_encode64(binary)
    return Base64.strict_encode64(binary).tr('+/', '-_').delete('=')
  end

  # Gets the current XChaCha20-Poly1305 module used by {JOSE::JWA::XChaCha20Poly1305 JOSE::JWA::XChaCha20Poly1305}, see {.xchacha20poly1305_module=} for default.
  # @return [Module]
  def self.xchacha20poly1305_module
    return JOSE::JWA::XChaCha20Poly1305.__implementation__
  end

  # Sets the current XChaCha20Poly1305 module used by {JOSE::JWA::XChaCha20Poly1305 JOSE::JWA::XChaCha20Poly1305}.
  #
  # Currently supported XChaCha20Poly1305 modules (first found is used as default):
  #
  #   * {https://github.com/cryptosphere/rbnacl `RbNaCl`}
  #
  # Additional modules that implement the functions specified in {JOSE::JWA::XChaCha20Poly1305 JOSE::JWA::XChaCha20Poly1305} may also be used.
  # @param [Module] mod
  # @return [Module]
  def self.xchacha20poly1305_module=(mod)
    JOSE::JWA::XChaCha20Poly1305.__implementation__ = mod
  end

private

  def self.__config_change__
    JOSE::JWA::Curve25519.__config_change__
    JOSE::JWA::Curve448.__config_change__
    JOSE::JWA::XChaCha20Poly1305.__config_change__
  end

  def self.sort_maps(term)
    case term
    when Hash, JOSE::Map
      return term.keys.sort.each_with_object(Hash.new) do |key, hash|
        hash[key] = sort_maps(term[key])
      end
    when Array
      return term.map do |item|
        sort_maps(item)
      end
    else
      return term
    end
  end

end

require 'jose/jwa'
require 'jose/jwe'
require 'jose/jwk'
require 'jose/jws'
require 'jose/jwt'
