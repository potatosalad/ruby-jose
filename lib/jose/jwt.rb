module JOSE
  # JWT stands for JSON Web Token which is defined in [RFC 7519](https://tools.ietf.org/html/rfc7519).
  #
  # ## Encryption Examples
  #
  # All of the example keys generated below can be found here: [https://gist.github.com/potatosalad/dd140560b2bdbdab886d](https://gist.github.com/potatosalad/dd140560b2bdbdab886d)
  #
  # See {JOSE::JWE JOSE::JWE} for more Encryption examples.
  #
  # ### A128GCM
  #
  #     !!!ruby
  #     jwk_oct128 = JOSE::JWK.generate_key([:oct, 16])
  #     jwt       = { "test" => true }
  #
  #     # A128GCM
  #     encrypted_a128gcm = JOSE::JWT.encrypt(jwk_oct128, { "alg" => "dir", "enc" => "A128GCM" }, jwt).compact
  #     # => "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIiwidHlwIjoiSldUIn0..yKs3KxBPBsp60bVv.lYrRQrT8GQQMG2OFCA.Z6GQkHT6K6VWxkOJBLFt3g"
  #     JOSE::JWT.decrypt(jwk_oct128, encrypted_a128gcm)
  #     # => [#<struct JOSE::JWT fields=JOSE::Map["test" => true]>,
  #     #  #<struct JOSE::JWE
  #     #   alg=#<JOSE::JWE::ALG_dir:0x007fd81c1023d0>,
  #     #   enc=#<struct JOSE::JWE::ENC_AES_GCM cipher_name="aes-128-gcm", bits=128, cek_len=16, iv_len=12>,
  #     #   zip=nil,
  #     #   fields=JOSE::Map["typ" => "JWT"]>]
  #
  # ## Signature Examples
  #
  # All of the example keys generated below can be found here: [https://gist.github.com/potatosalad/925a8b74d85835e285b9](https://gist.github.com/potatosalad/925a8b74d85835e285b9)
  #
  # See {JOSE::JWS JOSE::JWS} for more Signature examples.  For security purposes, {JOSE::JWT.verify_strict JOSE::JWT.verify_strict} is recommended over {JOSE::JWT.verify JOSE::JWT.verify}.
  #
  # ### HS256
  #
  #     !!!ruby
  #     # let's generate the key we'll use below and define our jwt
  #     jwk_hs256 = JOSE::JWK.generate_key([:oct, 16])
  #     jwt       = { "test" => true }
  #
  #     # HS256
  #     signed_hs256 = JOSE::JWT.sign(jwk_hs256, { "alg" => "HS256" }, jwt).compact
  #     # => "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0ZXN0Ijp0cnVlfQ.XYsFJDhfBZCAKnEZjR0WWd1l1ZPDD4bYpZYMHizexfQ"
  #
  #     # verify_strict is recommended over verify
  #     JOSE::JWT.verify_strict(jwk_hs256, ["HS256"], signed_hs256)
  #     # => [true,
  #     #  #<struct JOSE::JWT fields=JOSE::Map["test" => true]>,
  #     #  #<struct JOSE::JWS
  #     #   alg=#<struct JOSE::JWS::ALG_HMAC hmac=OpenSSL::Digest::SHA256>,
  #     #   b64=nil,
  #     #   fields=JOSE::Map["typ" => "JWT"]>]
  #
  #     # verify returns the same thing without "alg" whitelisting
  #     JOSE::JWT.verify(jwk_hs256, signed_hs256)
  #     # => [true,
  #     #  #<struct JOSE::JWT fields=JOSE::Map["test" => true]>,
  #     #  #<struct JOSE::JWS
  #     #   alg=#<struct JOSE::JWS::ALG_HMAC hmac=OpenSSL::Digest::SHA256>,
  #     #   b64=nil,
  #     #   fields=JOSE::Map["typ" => "JWT"]>]
  #
  #     # the default signing algorithm is also "HS256" based on the type of jwk used
  #     signed_hs256 == JOSE::JWT.sign(jwk_hs256, jwt).compact
  #     # => true
  class JWT < Struct.new(:fields)

    # Decode API

    # Converts a binary or map into a {JOSE::JWT JOSE::JWT}.
    #
    #     !!!ruby
    #     JOSE::JWT.from({ "test" => true })
    #     # => #<struct JOSE::JWT fields=JOSE::Map["test" => true]>
    #     JOSE::JWT.from("{\"test\":true}")
    #     # => #<struct JOSE::JWT fields=JOSE::Map["test" => true]>
    #
    # @param [JOSE::Map, Hash, String, JOSE::JWT, Array<JOSE::Map, Hash, String, JOSE::JWT>] object
    # @param [Hash] modules
    # @return [JOSE::JWT, Array<JOSE::JWT>]
    def self.from(object, modules = {})
      case object
      when JOSE::Map, Hash
        return from_map(object, modules)
      when String
        return from_binary(object, modules)
      when JOSE::JWT
        return object
      when Array
        return object.map { |obj| from(obj, modules) }
      else
        raise ArgumentError, "'object' must be a Hash, String, JOSE::JWT, or Array"
      end
    end

    # Converts a binary into a {JOSE::JWT JOSE::JWT}.
    # @param [String, Array<String>] object
    # @param [Hash] modules
    # @return [JOSE::JWT, Array<JOSE::JWT>]
    def self.from_binary(object, modules = {})
      case object
      when String
        return from_map(JOSE.decode(object), modules)
      when Array
        return object.map { |obj| from_binary(obj, modules) }
      else
        raise ArgumentError, "'object' must be a String or Array"
      end
    end

    # Reads file and calls {.from_binary} to convert into a {JOSE::JWT JOSE::JWT}.
    # @param [String] object
    # @param [Hash] modules
    # @return [JOSE::JWT]
    def self.from_file(file, modules = {})
      return from_binary(File.binread(file), modules)
    end

    # Converts a map into a {JOSE::JWT JOSE::JWT}.
    # @param [JOSE::Map, Hash, Array<JOSE::Map, Hash>] object
    # @param [Hash] modules
    # @return [JOSE::JWT, Array<JOSE::JWT>]
    def self.from_map(object, modules = {})
      case object
      when JOSE::Map, Hash
        return from_fields(JOSE::JWT.new(JOSE::Map.new(object)), modules)
      when Array
        return object.map { |obj| from_map(obj, modules) }
      else
        raise ArgumentError, "'object' must be a Hash or Array"
      end
    end

    # Encode API

    # Converts a {JOSE::JWT JOSE::JWT} into a binary.
    # @param [JOSE::Map, Hash, String, JOSE::JWT, Array<JOSE::Map, Hash, String, JOSE::JWT>] jwt
    # @return [String, Array<String>]
    def self.to_binary(jwt)
      if jwt.is_a?(Array)
        return from(jwt).map { |obj| obj.to_binary }
      else
        return from(jwt).to_binary
      end
    end

    # Converts a {JOSE::JWT JOSE::JWT} into a binary.
    # @return [String]
    def to_binary
      return JOSE.encode(to_map)
    end

    # Calls {.to_binary} on a {JOSE::JWT JOSE::JWT} and then writes the binary to `file`.
    # @param [JOSE::Map, Hash, String, JOSE::JWT] jwt
    # @param [String] file
    # @return [Fixnum] bytes written
    def self.to_file(jwt, file)
      return from(jwt).to_file(file)
    end

    # Calls {#to_binary} on a {JOSE::JWT JOSE::JWT} and then writes the binary to `file`.
    # @param [String] file
    # @return [Fixnum] bytes written
    def to_file(file)
      return File.binwrite(file, to_binary)
    end

    # Converts a {JOSE::JWT JOSE::JWT} into a map.
    # @param [JOSE::Map, Hash, String, JOSE::JWT, Array<JOSE::Map, Hash, String, JOSE::JWT>] jwt
    # @return [JOSE::Map, Array<JOSE::Map>]
    def self.to_map(jwt)
      if jwt.is_a?(Array)
        return from(jwt).map { |obj| obj.to_map }
      else
        return from(jwt).to_map
      end
    end

    # Converts a {JOSE::JWT JOSE::JWT} into a map.
    # @return [JOSE::Map]
    def to_map
      return fields
    end

    # API

    # Decrypts an encrypted {JOSE::JWT JOSE::JWT} using the `jwk`.
    # @see JOSE::JWE.block_decrypt
    # @param [JOSE::JWK] jwk
    # @param [JOSE::EncryptedBinary, JOSE::EncryptedMap]
    # @return [[JOSE::JWT, JOSE::JWE]]
    def self.decrypt(jwk, encrypted)
      decrypted, jwe = JOSE::JWK.block_decrypt(jwk, encrypted)
      return from_binary(decrypted), jwe
    end

    # Encrypts a {JOSE::JWT JOSE::JWT} using the `jwk` and the default block encryptor algorithm `jwe` for the key type.
    # @see JOSE::JWT#encrypt
    # @param [JOSE::JWK] jwk
    # @param [JOSE::JWE, JOSE::JWT] jwe
    # @param [JOSE::JWT] jwt
    # @return [JOSE::EncryptedMap]
    def self.encrypt(jwk, jwe, jwt = nil)
      if jwt.nil?
        jwt = jwe
        jwe = nil
      end
      return from(jwt).encrypt(jwk, jwe)
    end

    # Encrypts a {JOSE::JWT JOSE::JWT} using the `jwk` and the `jwe` algorithm.
    #
    # If `"typ"` is not specified in the `jwe`, `{ "typ" => "JWT" }` will be added.
    # @see JOSE::JWK.block_encrypt
    # @param [JOSE::JWK] jwk
    # @param [JOSE::JWE] jwe
    # @return [JOSE::EncryptedMap]
    def encrypt(jwk, jwe = nil)
      plain_text = to_binary
      if jwe.nil?
        jwk = JOSE::JWK.from(jwk)
        jwe = jwk.block_encryptor
      end
      if jwe.is_a?(Hash)
        jwe = JOSE::Map.new(jwe)
      end
      if jwe.is_a?(JOSE::Map) and not jwe.has_key?('typ')
        jwe = jwe.put('typ', 'JWT')
      end
      return JOSE::JWK.block_encrypt(jwk, plain_text, jwe)
    end

    # Merges map on right into map on left.
    # @param [JOSE::Map, Hash, String, JOSE::JWT] left
    # @param [JOSE::Map, Hash, String, JOSE::JWT] right
    # @return [JOSE::JWT]
    def self.merge(left, right)
      return from(left).merge(right)
    end

    # Merges object into current map.
    # @param [JOSE::Map, Hash, String, JOSE::JWT] object
    # @return [JOSE::JWT]
    def merge(object)
      object = case object
      when JOSE::Map, Hash
        object
      when String
        JOSE.decode(object)
      when JOSE::JWT
        object.to_map
      else
        raise ArgumentError, "'object' must be a Hash, String, or JOSE::JWT"
      end
      return JOSE::JWT.from_map(self.to_map.merge(object))
    end

    # Returns the decoded payload portion of a signed binary or map without verifying the signature.
    #
    #     !!!ruby
    #     JOSE::JWT.peek_payload("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0ZXN0Ijp0cnVlfQ.XYsFJDhfBZCAKnEZjR0WWd1l1ZPDD4bYpZYMHizexfQ")
    #     # => JOSE::Map["test" => true]
    #
    # @see JOSE::JWS.peek_payload
    # @param [JOSE::SignedBinary, String] signed
    # @return [JOSE::Map]
    def self.peek_payload(signed)
      return JOSE::Map.new(JOSE.decode(JOSE::JWS.peek_payload(signed)))
    end

    # Returns the decoded protected portion of a signed binary or map without verifying the signature.
    # @see JOSE::JWS.peek_protected
    # @param [JOSE::SignedBinary, String] signed
    # @return [String]
    def self.peek_protected(signed)
      return JOSE::JWS.peek_protected(signed)
    end

    # Returns the decoded signature portion of a signed binary or map without verifying the signature.
    # @see JOSE::JWS.peek_signature
    # @param [JOSE::SignedBinary, String] signed
    # @return [String]
    def self.peek_signature(signed)
      return JOSE::JWS.peek_signature(signed)
    end

    # Signs a {JOSE::JWT JOSE::JWT} using the `jwk` and the default signer algorithm `jws` for the key type.
    # @see JOSE::JWT#sign
    # @see JOSE::JWS.sign
    # @param [JOSE::JWK] jwk
    # @param [JOSE::JWS, JOSE::JWT] jws
    # @param [JOSE::JWT] jwt
    # @param [JOSE::Map, Hash] header
    # @return [JOSE::SignedMap]
    def self.sign(jwk, jws, jwt = nil, header = nil)
      if jwt.nil?
        jwt = jws
        jws = nil
      end
      return from(jwt).sign(jwk, jws, header)
    end

    # Signs a {JOSE::JWT JOSE::JWT} using the `jwk` and the `jws` algorithm.
    # @see JOSE::JWT#sign
    # @see JOSE::JWS.sign
    # @param [JOSE::JWK] jwk
    # @param [JOSE::JWS] jws
    # @param [JOSE::Map, Hash] header
    # @return [JOSE::SignedMap]
    def sign(jwk, jws = nil, header = nil)
      plain_text = to_binary
      if jws.nil?
        jwk = JOSE::JWK.from(jwk)
        jws = jwk.signer
      end
      jws = JOSE::JWS.from(jws).to_map
      if not jws.has_key?('typ')
        jws = jws.put('typ', 'JWT')
      end
      return JOSE::JWK.sign(jwk, plain_text, jws, header)
    end

    # Verifies the `signed` using the `jwk` and calls {JOSE::JWT.from JOST::JWT.from} on the payload.
    # @see JOSE::JWS.verify
    # @param [JOSE::JWK] jwk
    # @param [JOSE::SignedBinary, JOSE::SignedMap] signed
    # @return [[Boolean, JOSE::JWT, JOSE::JWS]]
    def self.verify(jwk, signed)
      verified, payload, jws = JOSE::JWK.verify(signed, jwk)
      jwt = from_binary(payload)
      return verified, jwt, jws
    end

    # Verifies the `signed` using the `jwk`, whitelists the `"alg"` using `allow`, and calls {JOSE::JWT.from JOST::JWT.from} on the payload.
    # @see JOSE::JWS.verify_strict
    # @param [JOSE::JWK] jwk
    # @param [Array<String>] allow
    # @param [JOSE::SignedBinary, JOSE::SignedMap] signed
    # @return [[Boolean, (JOSE::JWT, String), (JOSE::JWS, JOSE::Map)]]
    def self.verify_strict(jwk, allow, signed)
      verified, payload, jws = JOSE::JWK.verify_strict(signed, allow, jwk)
      jwt = payload
      if verified
        jwt = from_binary(payload)
      end
      return verified, jwt, jws
    end

  private

    def self.from_fields(jwt, modules)
      return jwt
    end

  end
end

require 'jose/jws/alg'
