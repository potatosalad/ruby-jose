module JOSE

  class EncryptedBinary < ::String
    # Expands a compacted encrypted binary or list of encrypted binaries into a map.
    # @see JOSE::JWE.expand
    # @return [JOSE::EncryptedMap]
    def expand
      return JOSE::JWE.expand(self)
    end

    # Returns the decoded ciphertext portion of a encrypted binary or map without decrypting the ciphertext.
    # @see JOSE::JWE.peek_ciphertext
    # @return [String]
    def peek_ciphertext
      return JOSE::JWE.peek_ciphertext(self)
    end

    # Returns the decoded encrypted key portion of a encrypted binary or map without decrypting the ciphertext.
    # @see JOSE::JWE.peek_encrypted_key
    # @return [String]
    def peek_encrypted_key
      return JOSE::JWE.peek_encrypted_key(self)
    end

    # Returns the decoded initialization vector portion of a encrypted binary or map without decrypting the ciphertext.
    # @see JOSE::JWE.peek_iv
    # @return [String]
    def peek_iv
      return JOSE::JWE.peek_iv(self)
    end

    # Returns the decoded protected portion of a encrypted binary or map without decrypting the ciphertext.
    # @see JOSE::JWE.peek_protected
    # @return [JOSE::Map]
    def peek_protected
      return JOSE::JWE.peek_protected(self)
    end

    # Returns the decoded tag portion of a encrypted binary or map without decrypting the ciphertext.
    # @see JOSE::JWE.peek_tag
    # @return [String]
    def peek_tag
      return JOSE::JWE.peek_tag(self)
    end
  end

  # Immutable encrypted Map structure based on {JOSE::Map JOSE::Map}.
  class EncryptedMap < JOSE::Map
    # Compacts an expanded encrypted map into a binary.
    # @see JOSE::JWE.compact
    # @return [JOSE::EncryptedBinary]
    def compact
      return JOSE::JWE.compact(self)
    end
  end

  # JWE stands for JSON Web Encryption which is defined in [RFC 7516](https://tools.ietf.org/html/rfc7516).
  #
  # ## Key Derivation Algorithms
  #
  # The following key derivation algorithms for the `"alg"` field are currently supported by {JOSE::JWE JOSE::JWE} (some may need the {JOSE.crypto_fallback= JOSE.crypto_fallback=} option to be enabled):
  #
  #   * `"A128GCMKW"`
  #   * `"A192GCMKW"`
  #   * `"A256GCMKW"`
  #   * `"A128KW"`
  #   * `"A192KW"`
  #   * `"A256KW"`
  #   * `"dir"`
  #   * `"ECDH-ES"`
  #   * `"ECDH-ES+A128KW"`
  #   * `"ECDH-ES+A192KW"`
  #   * `"ECDH-ES+A256KW"`
  #   * `"PBES2-HS256+A128KW"`
  #   * `"PBES2-HS384+A192KW"`
  #   * `"PBES2-HS512+A256KW"`
  #   * `"RSA1_5"`
  #   * `"RSA-OAEP"`
  #   * `"RSA-OAEP-256"`
  #
  # ## Encryption Algorithms
  #
  # The following encryption algorithms for the `"enc"` field are currently supported by {JOSE::JWE JOSE::JWE} (some may need the {JOSE.crypto_fallback= JOSE.crypto_fallback=} option to be enabled):
  #
  #   * `"A128CBC-HS256"`
  #   * `"A192CBC-HS384"`
  #   * `"A256CBC-HS512"`
  #   * `"A128GCM"`
  #   * `"A192GCM"`
  #   * `"A256GCM"`
  #
  # ## Compression Algorithms
  #
  # The following compression algorithms for the `"zip"` field are currently supported by {JOSE::JWE JOSE::JWE}:
  #
  #   * `"DEF"`
  #
  # ## Key Derivation Examples
  #
  # All of the examples below will use `"enc"` set to `"A128GCM"`, `"A192GCM"`, or `"A256GCM"` depending on the derived key size.
  #
  # The octet key used will typically be all zeroes of the required size in the form of `([0]*16).pack('C*')` (for a 128-bit key).
  #
  # All of the example keys generated below can be found here: [https://gist.github.com/potatosalad/dd140560b2bdbdab886d](https://gist.github.com/potatosalad/dd140560b2bdbdab886d)
  #
  #     !!!ruby
  #     # octet keys we'll use below
  #     jwk_oct128 = JOSE::JWK.from_oct(([0]*16).pack('C*'))
  #     jwk_oct192 = JOSE::JWK.from_oct(([0]*24).pack('C*'))
  #     jwk_oct256 = JOSE::JWK.from_oct(([0]*32).pack('C*'))
  #     jwk_secret = JOSE::JWK.from_oct("secret")
  #
  #     # EC keypairs we'll use below
  #     jwk_ec256_alice_sk = JOSE::JWK.generate_key([:ec, "P-256"])
  #     jwk_ec256_alice_pk = JOSE::JWK.to_public(jwk_ec256_alice_sk)
  #     jwk_ec256_bob_sk   = JOSE::JWK.generate_key([:ec, "P-256"])
  #     jwk_ec256_bob_pk   = JOSE::JWK.to_public(jwk_ec256_bob_sk)
  #
  #     # X25519 keypairs we'll use below
  #     jwk_x25519_alice_sk = JOSE::JWK.generate_key([:okp, :X25519])
  #     jwk_x25519_alice_pk = JOSE::JWK.to_public(jwk_x25519_alice_sk)
  #     jwk_x25519_bob_sk   = JOSE::JWK.generate_key([:okp, :X25519])
  #     jwk_x25519_bob_pk   = JOSE::JWK.to_public(jwk_x25519_bob_sk)
  #
  #     # X448 keypairs we'll use below
  #     jwk_x448_alice_sk = JOSE::JWK.generate_key([:okp, :X448])
  #     jwk_x448_alice_pk = JOSE::JWK.to_public(jwk_x448_alice_sk)
  #     jwk_x448_bob_sk   = JOSE::JWK.generate_key([:okp, :X448])
  #     jwk_x448_bob_pk   = JOSE::JWK.to_public(jwk_x448_bob_sk)
  #
  #     # RSA keypairs we'll use below
  #     jwk_rsa_sk = JOSE::JWK.generate_key([:rsa, 4096])
  #     jwk_rsa_pk = JOSE::JWK.to_public(jwk_rsa_sk)
  #
  # ### A128GCMKW, A192GCMKW, and A256GCMKW
  #
  #     !!!ruby
  #     # A128GCMKW
  #     encrypted_a128gcmkw = JOSE::JWE.block_encrypt(jwk_oct128, "{}", { "alg" => "A128GCMKW", "enc" => "A128GCM" }).compact
  #     # => "eyJhbGciOiJBMTI4R0NNS1ciLCJlbmMiOiJBMTI4R0NNIiwiaXYiOiJzODNFNjhPNjhsWlM5ZVprIiwidGFnIjoieF9Ea2M5dm1LMk5RQV8tU2hvTkFRdyJ9.8B2qX8fVEa-s61RsZXqkCg.J7yJ8sKLbUlzyor6.FRs.BhBwImTv9B14NwVuxmfU6A"
  #     JOSE::JWE.block_decrypt(jwk_oct128, encrypted_a128gcmkw).first
  #     # => "{}"
  #
  #     # A192GCMKW
  #     encrypted_a192gcmkw = JOSE::JWE.block_encrypt(jwk_oct192, "{}", { "alg" => "A192GCMKW", "enc" => "A192GCM" }).compact
  #     # => "eyJhbGciOiJBMTkyR0NNS1ciLCJlbmMiOiJBMTkyR0NNIiwiaXYiOiIxMkduZWQyTDB6NE5LZG83IiwidGFnIjoiM0thbG9iaER1Wmx5dE1YSjhjcXhZZyJ9.jJC4E1c6augIhvGDp3fquRfO-mnnud4F.S2NkKNGxBKTsCnKo.gZA.MvfhqSTeEN75H8HDyvfzRQ"
  #     JOSE::JWE.block_decrypt(jwk_oct192, encrypted_a192gcmkw).first
  #     # => "{}"
  #
  #     # A256GCMKW
  #     encrypted_a256gcmkw = JOSE::JWE.block_encrypt(jwk_oct256, "{}", { "alg" => "A256GCMKW", "enc" => "A256GCM" }).compact
  #     # => "eyJhbGciOiJBMjU2R0NNS1ciLCJlbmMiOiJBMjU2R0NNIiwiaXYiOiJHU3lFMTBLQURxZTczNUMzIiwidGFnIjoiR3dVbDJCbXRNWlVseDlXNEMtY0tQZyJ9.sSsbFw9z8WTkzBLvPMywSedTXXygFxfP9g5U2qpzUX8.eiVFfe7iojfK0AXb._v8.YVfk9dNrtS7wxbGqCVge-g"
  #     JOSE::JWE.block_decrypt(jwk_oct256, encrypted_a256gcmkw).first
  #     # => "{}"
  #
  # ### A128KW, A192KW, and A256KW
  #
  #     !!!ruby
  #     # A128KW
  #     encrypted_a128kw = JOSE::JWE.block_encrypt(jwk_oct128, "{}", { "alg" => "A128KW", "enc" => "A128GCM" }).compact
  #     # => "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4R0NNIn0.t4_Fb4kCl6BcS1cXnR4P4Xgm-jwVNsFl.RerKfWjzqqtLIUrz.JmE.ZDpVlWo-aQYM5la9eshwWw"
  #     JOSE::JWE.block_decrypt(jwk_oct128, encrypted_a128kw).first
  #     # => "{}"
  #
  #     # A192KW
  #     encrypted_a192kw = JOSE::JWE.block_encrypt(jwk_oct192, "{}", { "alg" => "A192KW", "enc" => "A192GCM" }).compact
  #     # => "eyJhbGciOiJBMTkyS1ciLCJlbmMiOiJBMTkyR0NNIn0.edpvNrztlNADbkwfq5YBJgqFBSH_Znv1Y1uXKNQ_13w.yCkEYTCPOKH6CoxZ.siw.zP_ZM9OEeX1FIdFjqNawtQ"
  #     JOSE::JWE.block_decrypt(jwk_oct192, encrypted_a192kw).first
  #     # => "{}"
  #
  #     # A256KW
  #     encrypted_a256kw = JOSE::JWE.block_encrypt(jwk_oct256, "{}", { "alg" => "A256KW", "enc" => "A256GCM" }).compact
  #     # => "eyJhbGciOiJBMjU2S1ciLCJlbmMiOiJBMjU2R0NNIn0.OvAhC1a2BoP_2SMIiZXwIHWPoIkD-Cosgp3nlpiTs8ySUBPfPzwG1g.4GeackYJbuBksAWA.HPE.vG0sGC2kuklH5xk8KXhyNA"
  #     JOSE::JWE.block_decrypt(jwk_oct256, encrypted_a256kw).first
  #     # => "{}"
  #
  # ### dir
  #
  # The `"dir"` key derivation algorithm is essentially just a pass-through to the underlying `"enc"` algorithm.
  #
  # The `"encrypted_key"` is not included in the protected header, so the key must be fully known by both parties.
  #
  #     !!!ruby
  #     # dir
  #     encrypted_dir = JOSE::JWE.block_encrypt(jwk_oct128, "{}", { "alg" => "dir", "enc" => "A128GCM" }).compact
  #     # => "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0..HdRR8O0kk_SvOjAS.rxo.JTMPGPKZZKVNlWV0RexsmQ"
  #     JOSE::JWE.block_decrypt(jwk_oct128, encrypted_dir).first
  #     # => "{}"
  #
  # ### ECDH-ES, ECDH-ES+A128KW, ECDH-ES+A192KW, and ECDH-ES+A256KW
  #
  # The `"ECDH-ES"` key derivation algorithm does not include the `"encrypted_key"` field in the protected header, similar to how `"dir"` functions.
  #
  # The size of the generated key is dependent on the `"enc"` setting (for example, `"A128GCM"` will generate a 128-bit key, `"A256GCM"` a 256-bit key, etc).
  #
  #     !!!ruby
  #     # ECDH-ES with EC keypairs
  #     encrypted_ecdhes_ec256_alice2bob = JOSE::JWE.block_encrypt([jwk_ec256_bob_pk, jwk_ec256_alice_sk], "{}", { "alg" => "ECDH-ES", "enc" => "A128GCM" }).compact
  #     # => "eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTEyOEdDTSIsImVwayI6eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6IjQ4UVUzUTBDeVN4d0piRXdXckpyWVhscDg4X2RWcEhUeHE0YXZjNjZoNVEiLCJ5IjoiWnpxcklOdE1NeEh4US1RQjcyUk1jZGxtRHNPSXdsS2hNcVZtX2dZV0MxNCJ9fQ..UssNrY5qEeFdluZY.R6g.32nlr0wHF2TwfL1UnBtIow"
  #     JOSE::JWE.block_decrypt([jwk_ec256_alice_pk, jwk_ec256_bob_sk], encrypted_ecdhes_ec256_alice2bob).first
  #     # => "{}"
  #
  #     # ECDH-ES with X25519 keypairs
  #     encrypted_ecdhes_x25519_alice2bob = JOSE::JWE.block_encrypt([jwk_x25519_bob_pk, jwk_x25519_alice_sk], "{}", { "alg" => "ECDH-ES", "enc" => "A128GCM" }).compact
  #     # => "eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTEyOEdDTSIsImVwayI6eyJjcnYiOiJYMjU1MTkiLCJrdHkiOiJPS1AiLCJ4IjoiZ0g3TjJwT0duenZfd0tBLUhqREZKTlVSZVhfdG05XzdiMkZSUjI3cXFYcyJ9fQ..T-0q42FPCUy3hlla.MHU.9TNP2jG5bN1vSvaesijdww"
  #     JOSE::JWE.block_decrypt([jwk_x25519_alice_pk, jwk_x25519_bob_sk], encrypted_ecdhes_x25519_alice2bob).first
  #     # => "{}"
  #
  #     # ECDH-ES with X448 keypairs
  #     encrypted_ecdhes_x448_alice2bob = JOSE::JWE.block_encrypt([jwk_x448_bob_pk, jwk_x448_alice_sk], "{}", { "alg" => "ECDH-ES", "enc" => "A128GCM" }).compact
  #     # => "eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTEyOEdDTSIsImVwayI6eyJjcnYiOiJYNDQ4Iiwia3R5IjoiT0tQIiwieCI6ImFFaHZISGxFM2V1Y3lsY0RNNzBMd1paY2dDRk9acXExNWM3YXZNMjJkcWZIUEtja1FZNmo3LXFfM19kMGI1cGVWZEFoNVoyQWZIWSJ9fQ..T-UNE-wOApuRH71r.Uj8.l8bIfhC1UPAPVWBV3wkc6A"
  #     JOSE::JWE.block_decrypt([jwk_x448_alice_pk, jwk_x448_bob_sk], encrypted_ecdhes_x448_alice2bob).first
  #     # => "{}"
  #
  # When decrypting with any of the `"ECDH-ES"` related algorithms, the other party's public key is recommended, but not required for decryption (the embedded Ephemeral Public Key will be used instead):
  #
  #     !!!ruby
  #     # decrypting the X448 example with and without the public key specified
  #     JOSE::JWE.block_decrypt([jwk_x448_alice_pk, jwk_x448_bob_sk], encrypted_ecdhes_x448_alice2bob).first
  #     # => "{}"
  #     JOSE::JWE.block_decrypt(jwk_x448_bob_sk, encrypted_ecdhes_x448_alice2bob).first
  #     # => "{}"
  #
  # The `"ECDH-ES+A128KW"`, `"ECDH-ES+A192KW"`, and `"ECDH-ES+A256KW"` key derivation algorithms do include the `"encrypted_key"` and the suffix after `"ECDH-ES+"` determines the key size (so `"ECDH-ES+A128KW"` computes a 128-bit key).
  #
  #     !!!ruby
  #     # ECDH-ES+A128KW with EC keypairs
  #     encrypted_ecdhesa128kw_alice2bob = JOSE::JWE.block_encrypt([jwk_ec256_bob_pk, jwk_ec256_alice_sk], "{}", { "alg" => "ECDH-ES+A128KW", "enc" => "A128GCM" }).compact
  #     # => "eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImVuYyI6IkExMjhHQ00iLCJlcGsiOnsiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiI0OFFVM1EwQ3lTeHdKYkV3V3JKcllYbHA4OF9kVnBIVHhxNGF2YzY2aDVRIiwieSI6Ilp6cXJJTnRNTXhIeFEtUUI3MlJNY2RsbURzT0l3bEtoTXFWbV9nWVdDMTQifX0.ZwuqXf7svd3SH0M-XYLjWz5JsN6xX03C.l8tt83EJjy86IovL.i5A.nw05dPUA0a18xdtvmHbhHA"
  #     JOSE::JWE::block_decrypt([jwk_ec256_alice_pk, jwk_ec256_bob_sk], encrypted_ecdhesa128kw_alice2bob).first
  #     # => "{}"
  #
  #     # ECDH-ES+A192KW with EC keypairs
  #     encrypted_ecdhesa192kw_alice2bob = JOSE::JWE.block_encrypt({jwk_ec256_bob_pk, jwk_ec256_alice_sk}, "{}", { "alg" => "ECDH-ES+A192KW", "enc" => "A192GCM" }).compact
  #     # => "eyJhbGciOiJFQ0RILUVTK0ExOTJLVyIsImVuYyI6IkExOTJHQ00iLCJlcGsiOnsiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiI0OFFVM1EwQ3lTeHdKYkV3V3JKcllYbHA4OF9kVnBIVHhxNGF2YzY2aDVRIiwieSI6Ilp6cXJJTnRNTXhIeFEtUUI3MlJNY2RsbURzT0l3bEtoTXFWbV9nWVdDMTQifX0.S9LZ1i_Lua_if4I83WcaCQ9yT5qqPI_NhCFR7tMiZDQ.kG3taKEjGeKDRTzs.H1s.oVGBFP63z4gd3e-R2d1cmA"
  #     JOSE::JWE.block_decrypt({jwk_ec256_alice_pk, jwk_ec256_bob_sk}, encrypted_ecdhesa192kw_alice2bob).first
  #     # => "{}"
  #
  #     # ECDH-ES+A256KW with EC keypairs
  #     encrypted_ecdhesa256kw_alice2bob = JOSE::JWE.block_encrypt({jwk_ec256_bob_pk, jwk_ec256_alice_sk}, "{}", { "alg" => "ECDH-ES+A256KW", "enc" => "A256GCM" }).compact
  #     # => "eyJhbGciOiJFQ0RILUVTK0EyNTZLVyIsImVuYyI6IkEyNTZHQ00iLCJlcGsiOnsiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiI0OFFVM1EwQ3lTeHdKYkV3V3JKcllYbHA4OF9kVnBIVHhxNGF2YzY2aDVRIiwieSI6Ilp6cXJJTnRNTXhIeFEtUUI3MlJNY2RsbURzT0l3bEtoTXFWbV9nWVdDMTQifX0.4KWy1-vRiJyNINF6mWYbUPPTVNG9ADfvvfpSDbddPTftz7GmUHUsuQ.IkRhtGH23R-9dFF3.9yk.RnALhnqWMHWCZFxqc-DU4A"
  #     JOSE::JWE.block_decrypt({jwk_ec256_alice_pk, jwk_ec256_bob_sk}, encrypted_ecdhesa256kw_alice2bob).first
  #     # => "{}"
  #
  # See {JOSE::JWK.box_encrypt JOSE::JWK.box_encrypt} for generating an Ephemeral Public Key based on the same curve as the supplied other party key in the same step.
  #
  # ### PBES2-HS256+A128KW, PBES2-HS384+A192KW, and PBES2-HS512+A256KW
  #
  #     !!!ruby
  #     # PBES2-HS256+A128KW
  #     encrypted_pbes2hs256a128kw = JOSE::JWE.block_encrypt(jwk_secret, "{}", { "alg" => "PBES2-HS256+A128KW", "enc" => "A128GCM" }).compact
  #     # => "eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJlbmMiOiJBMTI4R0NNIiwicDJjIjo0MDk2LCJwMnMiOiJRR0laNTlzbjRnQThySHBWYjFrSkd3In0.8WMQ0fysLiHU8AjpjkcqJGpYe53VRf2s.vVEb2ZtKmtPIw8M-.Cmg.GCjDtdKV6khqEuyZy2gUxw"
  #     JOSE::JWE.block_decrypt(jwk_secret, encrypted_pbes2hs256a128kw).first
  #     # => "{}"
  #
  #     # PBES2-HS384+A192KW
  #     encrypted_pbes2hs384a192kw = JOSE::JWE.block_encrypt(jwk_secret, "{}", { "alg" => "PBES2-HS384+A192KW", "enc" => "A192GCM" }).compact
  #     # => "eyJhbGciOiJQQkVTMi1IUzM4NCtBMTkyS1ciLCJlbmMiOiJBMTkyR0NNIiwicDJjIjo2MTQ0LCJwMnMiOiJKSDRjZ0hlNTZiU0prZ1d6VktpWWJCb0FzWEJBY1A1NiJ9.Ck5GvgXxmyac3jzs0lRavoRh6tI9nEs3lYkx8sdDzGw.IdxaPATMkQ8FYiYQ.uHk.rDU6ltWsTsw9vuvA73bgJQ"
  #     JOSE::JWE.block_decrypt(jwk_secret, encrypted_pbes2hs384a192kw).first
  #     # => "{}"
  #
  #     # PBES2-HS512+A256KW
  #     encrypted_pbes2hs512a256kw = JOSE::JWE.block_encrypt(jwk_secret, "{}", { "alg" => "PBES2-HS512+A256KW", "enc" => "A256GCM" }).compact
  #     # => "eyJhbGciOiJQQkVTMi1IUzUxMitBMjU2S1ciLCJlbmMiOiJBMjU2R0NNIiwicDJjIjo4MTkyLCJwMnMiOiJ6YWRiMVNmT1F4V1gyTHJrSVgwWDFGM2QzNlBIdUdxRVFzUDVhbWVnTk00In0.6SUVO9sSevqZrZ5yPX-JvJNJrzfIQeTTzrkWBHEqHra1_AITtwEe0A.0AaF_3ZlJOkRlqgb.W8I.jFWob73QTn52IFSIPEWHFA"
  #     JOSE::JWE.block_decrypt(jwk_secret, encrypted_pbes2hs512a256kw).first
  #     # => "{}"
  #
  # The `"p2s"` and `"p2i"` fields may also be specified to control the Salt and Iterations of the PBES2 Key Derivation Function, respectively.
  #
  # The default Salt is a randomly generated binary the same length of bytes as the key wrap (for example, `"PBES2-HS256+A128KW"` will generate a 16-byte Salt).
  #
  # The default Iterations is 32 times the number of bits specified by the key wrap (for example, `"PBES2-HS256+A128KW"` will have 4096 Iterations).
  #
  #     !!!ruby
  #     # let's setup the JWE header
  #     iterations = 8192
  #     salt = ([0]*32).pack('C*') # all zero 256-bit salt, for example usage only
  #     jwe = {
  #       "alg" => "PBES2-HS256+A128KW",
  #       "enc" => "A128GCM",
  #       "p2i" => iterations,
  #       "p2s" => JOSE.urlsafe_encode64(salt)
  #     }
  #     # PBES2-HS256+A128KW
  #     encrypted_pbes2 = JOSE::JWE.block_encrypt(jwk_secret, "{}", jwe).compact
  #     # => "eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJlbmMiOiJBMTI4R0NNIiwicDJjIjo0MDk2LCJwMmkiOjgxOTIsInAycyI6IkFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUEifQ.I7wcBmg7O_rOWpg1aak7wQWX84YtED6k.Rgh3f6Kzl5SZ1z7x.FNo.eyK1ySx4SGR-xC2EYNySQA"
  #     JOSE::JWE.block_decrypt(jwk_secret, encrypted_pbes2).first
  #     # => "{}"
  #
  # ### RSA1_5, RSA-OAEP, and RSA-OAEP-256
  #
  #     !!!ruby
  #     # RSA1_5
  #     encrypted_rsa1_5 = JOSE::JWE.block_encrypt(jwk_rsa_pk, "{}", { "alg" => "RSA1_5", "enc" => "A128GCM" }).compact
  #     # => "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4R0NNIn0.NlndPTqULN1vArshEzfEXY0nHCf4ubsTK9iHAeIxL85fReYrYG8EDB2_IirUneavvHSa-hsVLXNzBu0F9OY3TRFAIuJ8Jt1tqZZEhHZ97vzTEIjdlPNctGNI11-mhNCJ0doSvx9T4ByngaAFtJnRoR2cqbJkJFGja60fHtO0CfKLW5XzPf0NAhr8Tof-5IJfbNpMcC_LdCItJ6i8cuj4i5pG_CikOKDrNzbaBP72200_kl_-YaLDMA4tVb2YjWksY5Vau0Hz16QvI9QwDIcIDLYPAlTlDrU7s_FfmO_89S9Z69-lc_OBG7x2CYzIhB-0wzx753nZRl_WNJKi1Ya_AV552FEqVUhR-SuKcyrTA9OwkKC2JoL3lFqsCL9jkZkBrVREQlT0cxNI_AInyx5FHNLBbdtkz0JQbvzMJ854RP0V_eTlI5u8DZ42aOTRMBLHPi-4gP0J_CGWyKDQreXEEF6LSuLJb1cGk-NX1Vd85aARstQPuOoy7pWJjPvBEKEib70fjkUuMA0Atid-5BusQLKc1H-D6c5HIFH0DgYtXhN6AtQ_fmqw1F_X1JrGnYiYGzJCD2hh0Yt2UJZoCuHlPKk8aM5L3lNU3AISb1soSQl3hfX8Skb817ffC7jYezdhZc12cRNzOPAYqJYjN2eDlQhx-gpFjVzc-W1bFG8Yijo.grliT3M1iZ48aSY9.F4Y.pBRqIGZ4Q_fI1kmeAggvRg"
  #     JOSE::JWE.block_decrypt(jwk_rsa_sk, encrypted_rsa1_5).first
  #     # => "{}"
  #
  #     # RSA-OAEP
  #     encrypted_rsaoaep = JOSE::JWE.block_encrypt(jwk_rsa_pk, "{}", { "alg" => "RSA-OAEP", "enc" => "A128GCM" }).compact
  #     # => "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExMjhHQ00ifQ.YZfGKTTU2KuvwIMpSYadbNmGzWIbLrwRYD8JvZAWkvcnFeky09S04VadRNPXmCBSl4EF1K7oBm0fiYXuvNbLFNKYT_Jo_y6Lb-XsP--BZKaEcq6wIdZ4-xTJ7YYX5dfco_cMknZLG8W2sQRwtWopisn9NyzSpfGNlYqeJqjpoJy0qnO8yZeEYeadwoVF9-XZfYwvMjEt7HORqBIPF1JIaOYTQ-LQBvya6XYhOR7dkSnuCZ_ITGW5ZbPvzOILSMW_3Ixe78ncfO2gxF6AiLh02oTLsOSrF9xDlJvuU0k1TdkNWtGroeP_WVbXEO7O_GI5LVW-cDzoVm5ZCQs2Df0018-qDxFyY9xhKS9aNDi_btiarstXMSz3EkOfPhWR_IzlVyUkYnzs3GS993gKLQ0Tk-ipvOT9Bcw9VTLLK3-f5YSkf51IA---hPFlxVlboH9bmTXlT4JzSbErQEYp3JuXjOP7FQn0OPko5Utqbbm41XBEJhUpBNhjrBGDspsMxML_eJdyzBgA5UyNfdCEQ2vM1pCegxG_hSKAhCKVNn71wW4O_y_eqUcoyhjB7HtVxiF29jzNUKF-y14171L4-mxsIpixaM1ofnayWMiherVP0Wz2MXkzWB0AUv8c3kNEJIh3oeyrczWwzpmeCh1Bq7-J4D6aaFjyGFcm-03_QZmfwho.ymxveKBeRuaZ8HzD.3H4.6oKLh2NouhPGpO1dmA-tTg"
  #     JOSE::JWE.block_decrypt(jwk_rsa_sk, encrypted_rsaoaep).first
  #     # => "{}"
  #
  #     # RSA-OAEP-256
  #     encrypted_rsaoaep256 = JOSE::JWE.block_encrypt(jwk_rsa_pk, "{}", { "alg" => "RSA-OAEP-256", "enc" => "A128GCM" }).compact
  #     # => "eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMTI4R0NNIn0.OW9Hy9qpOIgVueODQXcWIUw_-Sm3UFGtxosyOAaI6JUQFt8q-iEtKkUp4NHrOlczO6tP5t8zRKdNXFfCm9QZk6F9PsSO-NzE2-DV1ANAMck-CDfGTK0mwG5U_KZwlObSgU0gxf87K49Wuno1rWlHWzJb__C_hCJXi_aQW17tLmbuTpJMkB0NTCKX3y6QaxvynP98jqwMJT6uGmE3AeuZYhPGzAOWbltbWyw-TqWqyLJirAUY_fvDNsKt1TDrTd9216TK5y7RQeUtdGfbuYK9lt2TIwfh9ycAHd7SANH_YJc2cKYa3e6CgqnQAjVpbhpogBz5sz5HaK95XYbXOdnYyHQ00gS44YquiQCvX331UgEWnthtmYwDZfnCxTkPydafGOBsjaagGvV2tQtxUKW3JmVChF97bNj5lQZ7rAkyooxx-k3IMT0005x6_74O5tXGN5fb7oyT3Mx_NZ5dKzlYAA_V8oOpNslaFhV5K5Q_-hRkUsEPWdaD5s2uS9Z7l7ot39CzzTKDj65f2eCTWFReFKOjhabCL4ZiFXbElB3dA3y5FdxXPAfe6N31G9ynalx1JIcrEaRb8sdqk6U6uC3s3DpkoRSnp3osBJOxxuk_Lgb-ZM9d8UuRVj4W78-qjfX_lcG1RlRmlYoDIU03ly0UfRWi-7HmpPECrGTsGZEfULg.J-txckmMXEi-bZVh.Rbw.D7UpSkticmDCGiNyLVggLg"
  #     JOSE::JWE.block_decrypt(jwk_rsa_sk, encrypted_rsaoaep256).first
  #     # => "{}"
  #
  # ## Encryption Examples
  #
  # All of the examples below will use `"alg"` set to `"dir"` passing the key directly to the Encryption Algorithm.
  #
  # The octet key used will typically be all zeroes of the required size in the form of `([0]*16).pack('C*')` (for a 128-bit key).
  #
  # All of the example keys generated below can be found here: [https://gist.github.com/potatosalad/dd140560b2bdbdab886d](https://gist.github.com/potatosalad/dd140560b2bdbdab886d)
  #
  #     !!!ruby
  #     # octet keys we'll use below
  #     jwk_oct128 = JOSE::JWK.from_oct(([0]*16).pack('C*'))
  #     jwk_oct192 = JOSE::JWK.from_oct(([0]*24).pack('C*'))
  #     jwk_oct256 = JOSE::JWK.from_oct(([0]*32).pack('C*'))
  #     jwk_oct384 = JOSE::JWK.from_oct(([0]*48).pack('C*'))
  #     jwk_oct512 = JOSE::JWK.from_oct(([0]*64).pack('C*'))
  #
  # ### A128CBC-HS256, A192CBC-HS384, and A256CBC-HS512
  #
  #     !!!ruby
  #     # A128CBC-HS256
  #     encrypted_a128cbchs256 = JOSE::JWE.block_encrypt(jwk_oct256, "{}", { "alg" => "dir", "enc" => "A128CBC-HS256" }).compact
  #     # => "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..bxps64-UIQoFvhkjr05e9A.HrtJ3AqrqJ4f5PHjGseHYw.kopJoTDxk34IVhheoToLSA"
  #     JOSE::JWE.block_decrypt(jwk_oct256, encrypted_a128cbchs256).first
  #     # => "{}"
  #
  #     # A192CBC-HS384
  #     encrypted_a192cbchs384 = JOSE::JWE.block_encrypt(jwk_oct384, "{}", { "alg" => "dir", "enc" => "A192CBC-HS384" }).compact
  #     # => "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTkyQ0JDLUhTMzg0In0..3zSCHwvHrcxsNyssIgEBRA.XB70tUoQZlnOgY5ygMxfKA.Avl7Z8jCpShh3_iTcPcU3Woh6E9ykNyB"
  #     JOSE::JWE.block_decrypt(jwk_oct384, encrypted_a192cbchs384).first
  #     # => "{}"
  #
  #     # A256CBC-HS512
  #     encrypted_a256cbchs512 = JOSE::JWE.block_encrypt(jwk_oct512, "{}", { "alg" => "dir", "enc" => "A256CBC-HS512" }).compact
  #     # => "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0..mqMhkWAMF7HmW_Nu1ERUzQ.bzd-tmykuru0Lu_rsNZ2ow.mlOFO8JcC_UJ35TsZgiUeEwAjRDs6cwfN7Umyzm7mmY"
  #     JOSE::JWE.block_decrypt(jwk_oct512, encrypted_a256cbchs512).first
  #     # => "{}"
  #
  # ### A128GCM, A192GCM, and A256GCM
  #
  #     !!!ruby
  #     # A128GCM
  #     encrypted_a128gcm = JOSE::JWE.block_encrypt(jwk_oct128, "{}", { "alg" => "dir", "enc" => "A128GCM" }).compact
  #     # => "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0..pPF4SbzGZwxS1J-M.Ic0.qkHuC-hOO44HPlykBJLSsA"
  #     JOSE::JWE.block_decrypt(jwk_oct128, encrypted_a128gcm).first
  #     # => "{}"
  #
  #     # A192GCM
  #     encrypted_a192gcm = JOSE::JWE.block_encrypt(jwk_oct192, "{}", { "alg" => "dir", "enc" => "A192GCM" }).compact
  #     # => "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTkyR0NNIn0..muNgk2GFW9ATwqqZ.bvE.gYvC0G6DAodJdyrUqLw7Iw"
  #     JOSE::JWE.block_decrypt(jwk_oct192, encrypted_a192gcm).first
  #     # => "{}"
  #
  #     # A256GCM
  #     encrypted_a256gcm = JOSE::JWE.block_encrypt(jwk_oct256, "{}", { "alg" => "dir", "enc" => "A256GCM" }).compact
  #     # => "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..rDTJhd5ja5pDAYtn.PrM.MQdLgiVXQsG_cLas93ZEHw"
  #     JOSE::JWE.block_decrypt(jwk_oct256, encrypted_a256gcm).first
  #     # => "{}"
  #
  # ## Compression Examples
  #
  # All of the examples below will use `"alg"` set to `"dir"` passing the key directly to the Encryption Algorithm (`"enc"` is set to `"A128GCM"`).
  #
  # The octet key used will typically be all zeroes of the required size in the form of `([0]*16).pack('C*')` (for a 128-bit key).
  #
  # All of the example keys generated below can be found here: [https://gist.github.com/potatosalad/dd140560b2bdbdab886d](https://gist.github.com/potatosalad/dd140560b2bdbdab886d)
  #
  #     !!!ruby
  #     # octet keys we'll use below
  #     jwk_oct128 = JOSE::JWK.from_oct(([0]*16).pack('C*'))
  #
  # ### DEF
  #
  #     !!!ruby
  #     # DEF
  #     encrypted_def = JOSE::JWE.block_encrypt(jwk_oct128, "{}", { "alg" => "dir", "enc" => "A128GCM", "zip" => "DEF" }).compact
  #     # => "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIiwiemlwIjoiREVGIn0..Vvr0vlKWE9rAJ8CR.UpOz7w10Uc9pMg.Pctxzz0ijPSOY8zyRcbjww"
  #     JOSE::JWE.block_decrypt(jwk_oct128, encrypted_def).first
  #     # => "{}"
  class JWE < Struct.new(:alg, :enc, :zip, :fields)

    # Decode API

    # Converts a binary or map into a {JOSE::JWE JOSE::JWE}.
    #
    #     !!!ruby
    #     JOSE::JWE.from({ "alg" => "dir" })
    #     # => #<struct JOSE::JWE
    #     #  alg=#<struct JOSE::JWE::ALG_dir direct=true>,
    #     #  enc=nil,
    #     #  zip=nil,
    #     #  fields=JOSE::Map[]>
    #     JOSE::JWE.from("{\"alg\":\"dir\"}")
    #     # => #<struct JOSE::JWE
    #     #  alg=#<struct JOSE::JWE::ALG_dir direct=true>,
    #     #  enc=nil,
    #     #  zip=nil,
    #     #  fields=JOSE::Map[]>
    #
    # There are 3 keys which can have custom modules defined for them:
    #
    #   * `"alg"` - must implement {JOSE::JWE::ALG JOSE::JWE::ALG}
    #   * `"enc"` - must implement {JOSE::JWE::ENC JOSE::JWE::ENC}
    #   * `"zip"` - must implement {JOSE::JWE::ZIP JOSE::JWE::ZIP}
    #
    # For example:
    #
    #     !!!ruby
    #     JOSE::JWE.from({ "alg" => "dir", "zip" => "custom" }, { zip: MyCustomCompress })
    #     # => #<struct JOSE::JWE
    #     #  alg=#<struct JOSE::JWE::ALG_dir direct=true>,
    #     #  enc=nil,
    #     #  zip=#<MyCustomAlgorithm:0x007f8c5419ff68>,
    #     #  fields=JOSE::Map[]>
    #
    # @param [JOSE::Map, Hash, String, JOSE::JWE, Array<JOSE::Map, Hash, String, JOSE::JWE>] object
    # @param [Hash] modules
    # @return [JOSE::JWE, Array<JOSE::JWE>]
    def self.from(object, modules = {})
      case object
      when JOSE::Map, Hash
        return from_map(object, modules)
      when String
        return from_binary(object, modules)
      when JOSE::JWE
        return object
      when Array
        return object.map { |obj| from(obj, modules) }
      else
        raise ArgumentError, "'object' must be a Hash, String, JOSE::JWE, or Array"
      end
    end

    # Converts a binary into a {JOSE::JWE JOSE::JWE}.
    # @param [String, Array<String>] object
    # @param [Hash] modules
    # @return [JOSE::JWE, Array<JOSE::JWE>]
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

    # Reads file and calls {.from_binary} to convert into a {JOSE::JWE JOSE::JWE}.
    # @param [String] object
    # @param [Hash] modules
    # @return [JOSE::JWE]
    def self.from_file(file, modules = {})
      return from_binary(File.binread(file), modules)
    end

    # Converts a map into a {JOSE::JWE JOSE::JWE}.
    # @param [JOSE::Map, Hash, Array<JOSE::Map, Hash>] object
    # @param [Hash] modules
    # @return [JOSE::JWE, Array<JOSE::JWE>]
    def self.from_map(object, modules = {})
      case object
      when JOSE::Map, Hash
        return from_fields(JOSE::JWE.new(nil, nil, nil, JOSE::Map.new(object)), modules)
      when Array
        return object.map { |obj| from_map(obj, modules) }
      else
        raise ArgumentError, "'object' must be a Hash or Array"
      end
    end

    # Encode API

    # Converts a {JOSE::JWE JOSE::JWE} into a binary.
    # @param [JOSE::Map, Hash, String, JOSE::JWE, Array<JOSE::Map, Hash, String, JOSE::JWE>] jwe
    # @return [String, Array<String>]
    def self.to_binary(jwe)
      if jwe.is_a?(Array)
        return from(jwe).map { |obj| obj.to_binary }
      else
        return from(jwe).to_binary
      end
    end

    # Converts a {JOSE::JWE JOSE::JWE} into a binary.
    # @return [String]
    def to_binary
      return JOSE.encode(to_map)
    end

    # Calls {.to_binary} on a {JOSE::JWE JOSE::JWE} and then writes the binary to `file`.
    # @param [JOSE::Map, Hash, String, JOSE::JWE] jwe
    # @param [String] file
    # @return [Fixnum] bytes written
    def self.to_file(jwe, file)
      return from(jwe).to_file(file)
    end

    # Calls {#to_binary} on a {JOSE::JWE JOSE::JWE} and then writes the binary to `file`.
    # @param [String] file
    # @return [Fixnum] bytes written
    def to_file(file)
      return File.binwrite(file, to_binary)
    end

    # Converts a {JOSE::JWE JOSE::JWE} into a map.
    # @param [JOSE::Map, Hash, String, JOSE::JWE, Array<JOSE::Map, Hash, String, JOSE::JWE>] jwe
    # @return [JOSE::Map, Array<JOSE::Map>]
    def self.to_map(jwe)
      if jwe.is_a?(Array)
        return from(jwe).map { |obj| obj.to_map }
      else
        return from(jwe).to_map
      end
    end

    # Converts a {JOSE::JWE JOSE::JWE} into a map.
    # @return [JOSE::Map]
    def to_map
      if zip.nil?
        return alg.to_map(enc.to_map(fields))
      else
        return alg.to_map(enc.to_map(zip.to_map(fields)))
      end
    end

    # API

    # Decrypts the `encrypted` binary or map using the `key`.
    #
    #     !!!ruby
    #     jwk = JOSE::JWK.from({"k" => "STlqtIOhWJjoVnYjUjxFLZ6oN1oB70QARGSTWQ_5XgM", "kty" => "oct"})
    #     # => #<struct JOSE::JWK
    #     #  keys=nil,
    #     #  kty=#<struct JOSE::JWK::KTY_oct oct="I9j\xB4\x83\xA1X\x98\xE8Vv#R<E-\x9E\xA87Z\x01\xEFD\x00Dd\x93Y\x0F\xF9^\x03">,
    #     #  fields=JOSE::Map[]>
    #     JOSE::JWE.block_decrypt(jwk, "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..jBt5tTa1Q0N3uFPEkf30MQ.Ei49MvTLLje7bsZ5EZCZMA.gMWOAmhZSq9ksHCZm6VSoA")
    #     # => ["{}",
    #     #  #<struct JOSE::JWE
    #     #   alg=#<struct JOSE::JWE::ALG_dir direct=true>,
    #     #   enc=
    #     #    #<struct JOSE::JWE::ENC_AES_CBC_HMAC
    #     #     cipher_name="aes-128-cbc",
    #     #     bits=256,
    #     #     cek_len=32,
    #     #     iv_len=16,
    #     #     enc_len=16,
    #     #     mac_len=16,
    #     #     tag_len=16,
    #     #     hmac=OpenSSL::Digest::SHA256>,
    #     #   zip=nil,
    #     #   fields=JOSE::Map[]>]
    #
    # @see JOSE::JWE.block_encrypt
    # @param [JOSE::JWK, [JOSE::JWK, JOSE::JWK]] key
    # @param [JOSE::EncryptedBinary, JOSE::EncryptedMap, Hash, String] encrypted
    # @return [[String, JOSE::JWE]]
    def self.block_decrypt(key, encrypted)
      if encrypted.is_a?(String)
        encrypted = JOSE::JWE.expand(encrypted)
      end
      if encrypted.is_a?(Hash)
        encrypted = JOSE::EncryptedMap.new(encrypted)
      end
      if encrypted.is_a?(JOSE::Map) and encrypted['ciphertext'].is_a?(String) and encrypted['encrypted_key'].is_a?(String) and encrypted['iv'].is_a?(String) and encrypted['protected'].is_a?(String) and encrypted['tag'].is_a?(String)
        jwe = from_binary(JOSE.urlsafe_decode64(encrypted['protected']))
        encrypted_key = JOSE.urlsafe_decode64(encrypted['encrypted_key'])
        iv = JOSE.urlsafe_decode64(encrypted['iv'])
        cipher_text = JOSE.urlsafe_decode64(encrypted['ciphertext'])
        cipher_tag = JOSE.urlsafe_decode64(encrypted['tag'])
        if encrypted['aad'].is_a?(String)
          concat_aad = [encrypted['protected'], '.', encrypted['aad']].join
          return jwe.block_decrypt(key, concat_aad, cipher_text, cipher_tag, encrypted_key, iv), jwe
        else
          return jwe.block_decrypt(key, encrypted['protected'], cipher_text, cipher_tag, encrypted_key, iv), jwe
        end
      else
        raise ArgumentError, "'encrypted' is not a valid encrypted String, Hash, or JOSE::Map"
      end
    end

    # Decrypts the `cipher_text` binary using the `key`, `aad`, `cipher_tag`, `encrypted_key`, and `iv`.
    # @see JOSE::JWE.block_decrypt
    # @param [JOSE::JWK, [JOSE::JWK, JOSE::JWK]] key
    # @param [String] aad
    # @param [String] cipher_text
    # @param [String] cipher_tag
    # @param [String] encrypted_key
    # @param [String] iv
    # @return [[String, JOSE::JWE]]
    def block_decrypt(key, aad, cipher_text, cipher_tag, encrypted_key, iv)
      cek = key_decrypt(key, encrypted_key)
      return uncompress(enc.block_decrypt([aad, cipher_text, cipher_tag], cek, iv))
    end

    # Encrypts the `block` using the `key`, `cek`, `iv`, and algorithm specified by the `jwe`.
    #
    #     !!!ruby
    #     jwk = JOSE::JWK.from({"k" => "STlqtIOhWJjoVnYjUjxFLZ6oN1oB70QARGSTWQ_5XgM", "kty" => "oct"})
    #     # => #<struct JOSE::JWK
    #     #  keys=nil,
    #     #  kty=#<struct JOSE::JWK::KTY_oct oct="I9j\xB4\x83\xA1X\x98\xE8Vv#R<E-\x9E\xA87Z\x01\xEFD\x00Dd\x93Y\x0F\xF9^\x03">,
    #     #  fields=JOSE::Map[]>
    #     JOSE::JWE.block_encrypt(jwk, "{}", { "alg" => "dir", "enc" => "A128CBC-HS256" })
    #     # => JOSE::EncryptedMap[
    #     #  "tag" => "tSGaAlI2xiMThBZ9XTW2AQ",
    #     #  "ciphertext" => "c2T5O6WafTCKEX5R_9D-LQ",
    #     #  "encrypted_key" => "",
    #     #  "iv" => "U56zV4sW4bOovxeXcz7fUg",
    #     #  "protected" => "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0"]
    #
    # @see JOSE::JWE.block_decrypt
    # @param [JOSE::JWK, [JOSE::JWK, JOSE::JWK]] key
    # @param [String, [String, String]] block
    # @param [JOSE::JWE] jwe
    # @param [String] cek
    # @param [String] iv
    # @return [JOSE::EncryptedMap]
    def self.block_encrypt(key, block, jwe, cek = nil, iv = nil)
      return from(jwe).block_encrypt(key, block, cek, iv)
    end

    # Encrypts the `block` binary using the `key`, `cek`, and `iv`.
    # @see JOSE::JWE.block_encrypt
    # @param [JOSE::JWK, [JOSE::JWK, JOSE::JWK]] key
    # @param [String, [String, String]] block
    # @param [String] cek
    # @param [String] iv
    # @return [JOSE::EncryptedMap]
    def block_encrypt(key, block, cek = nil, iv = nil)
      jwe = self
      if cek.nil?
        cek, jwe = next_cek(key)
      end
      iv ||= jwe.next_iv
      aad, plain_text = block
      if plain_text.nil?
        plain_text = aad
        aad = nil
      end
      encrypted_key, jwe = jwe.key_encrypt(key, cek)
      protected_binary = JOSE.urlsafe_encode64(jwe.to_binary)
      if aad.nil?
        cipher_text, cipher_tag = enc.block_encrypt([protected_binary, jwe.compress(plain_text)], cek, iv)
        return JOSE::EncryptedMap[
          'ciphertext'    => JOSE.urlsafe_encode64(cipher_text),
          'encrypted_key' => JOSE.urlsafe_encode64(encrypted_key),
          'iv'            => JOSE.urlsafe_encode64(iv),
          'protected'     => protected_binary,
          'tag'           => JOSE.urlsafe_encode64(cipher_tag)
        ]
      else
        aad_b64 = JOSE.urlsafe_encode64(aad)
        concat_aad = [protected_binary, '.', aad_b64].join
        cipher_text, cipher_tag = enc.block_encrypt([concat_aad, jwe.compress(plain_text)], cek, iv)
        return JOSE::EncryptedMap[
          'aad'           => aad_b64,
          'ciphertext'    => JOSE.urlsafe_encode64(cipher_text),
          'encrypted_key' => JOSE.urlsafe_encode64(encrypted_key),
          'iv'            => JOSE.urlsafe_encode64(iv),
          'protected'     => protected_binary,
          'tag'           => JOSE.urlsafe_encode64(cipher_tag)
        ]
      end
    end

    # Compacts an expanded encrypted map into a binary.
    #
    #     !!!ruby
    #     JOSE::JWE.compact({
    #       "ciphertext" => "Ei49MvTLLje7bsZ5EZCZMA",
    #       "encrypted_key" => "",
    #       "iv" => "jBt5tTa1Q0N3uFPEkf30MQ",
    #       "protected" => "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    #       "tag" => "gMWOAmhZSq9ksHCZm6VSoA"
    #     })
    #     # => "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..jBt5tTa1Q0N3uFPEkf30MQ.Ei49MvTLLje7bsZ5EZCZMA.gMWOAmhZSq9ksHCZm6VSoA"
    #
    # @see JOSE::JWE.expand
    # @param [JOSE::EncryptedMap, JOSE::Map, Hash] map
    # @return [JOSE::EncryptedBinary]
    def self.compact(map)
      if map.is_a?(Hash) or map.is_a?(JOSE::Map)
        if map.has_key?('aad')
          raise ArgumentError, "'map' with 'aad' cannot be compacted"
        end
        return JOSE::EncryptedBinary.new([
          map['protected'] || '',
          '.',
          map['encrypted_key'] || '',
          '.',
          map['iv'] || '',
          '.',
          map['ciphertext'] || '',
          '.',
          map['tag'] || ''
        ].join)
      else
        raise ArgumentError, "'map' must be a Hash or a JOSE::Map"
      end
    end

    # Compresses the `plain_text` using the `"zip"` algorithm specified by the `jwe`.
    #
    #     !!!ruby
    #     JOSE::JWE.compress("{}", { "alg" => "dir", "zip" => "DEF" })
    #     # => "x\x9C\xAB\xAE\x05\x00\x01u\x00\xF9"
    #
    # @param [String] plain_text
    # @param [JOSE::JWE] jwe
    # @return [String]
    def self.compress(plain_text, jwe)
      return from(jwe).compress(plain_text)
    end

    # Compresses the `plain_text` using the `"zip"` algorithm specified by the `jwe`.
    # @see JOSE::JWE.compress
    # @param [String] plain_text
    # @return [String]
    def compress(plain_text)
      if zip.nil?
        return plain_text
      else
        return zip.compress(plain_text)
      end
    end

    # Expands a compacted encrypted binary into a map.
    #
    #     !!!ruby
    #     JOSE::JWE.expand("eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..jBt5tTa1Q0N3uFPEkf30MQ.Ei49MvTLLje7bsZ5EZCZMA.gMWOAmhZSq9ksHCZm6VSoA")
    #     # => JOSE::EncryptedMap[
    #     #  "tag" => "gMWOAmhZSq9ksHCZm6VSoA",
    #     #  "ciphertext" => "Ei49MvTLLje7bsZ5EZCZMA",
    #     #  "encrypted_key" => "",
    #     #  "iv" => "jBt5tTa1Q0N3uFPEkf30MQ",
    #     #  "protected" => "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0"]
    #
    # @see JOSE::JWE.compact
    # @param [JOSE::EncryptedBinary, String] binary
    # @return [JOSE::EncryptedMap]
    def self.expand(binary)
      if binary.is_a?(String)
        parts = binary.split('.')
        if parts.length == 5
          protected_binary, encrypted_key, initialization_vector, cipher_text, authentication_tag = parts
          return JOSE::EncryptedMap[
            'ciphertext'    => cipher_text,
            'encrypted_key' => encrypted_key,
            'iv'            => initialization_vector,
            'protected'     => protected_binary,
            'tag'           => authentication_tag
          ]
        else
          raise ArgumentError, "'binary' is not a valid encrypted String"
        end
      else
        raise ArgumentError, "'binary' must be a String"
      end
    end

    # Generates a new {JOSE::JWK JOSE::JWK} based on the algorithms of the specified {JOSE::JWE JOSE::JWE}.
    #
    #     !!!ruby
    #     JOSE::JWE.generate_key({"alg" => "dir", "enc" => "A128GCM"})
    #     # => #<struct JOSE::JWK
    #     #  keys=nil,
    #     #  kty=#<struct JOSE::JWK::KTY_oct oct="\xED4\x19\x14\xA1\xDB\xB5\xCF*\xAE\xEE7\xDA\xDE\xA9\xCB">,
    #     #  fields=JOSE::Map["alg" => "dir", "enc" => "A128GCM", "use" => "enc"]>
    #
    # @param [JOSE::Map, Hash, String, JOSE::JWE, Array<JOSE::Map, Hash, String, JOSE::JWE>] jwe
    # @param [Hash] modules
    # @return [JOSE::JWK, Array<JOSE::JWK>]
    def self.generate_key(jwe, modules = {})
      if jwe.is_a?(Array)
        return from(jwe, modules).map { |obj| obj.generate_key }
      else
        return from(jwe, modules).generate_key
      end
    end

    # Generates a new {JOSE::JWK JOSE::JWK} based on the algorithms of the specified {JOSE::JWE JOSE::JWE}.
    #
    # @see JOSE::JWE.generate_key
    # @return [JOSE::JWK]
    def generate_key
      return alg.generate_key(fields, enc)
    end

    # Decrypts the `encrypted_key` using the `key` and the `"alg"` and `"enc"` specified by the `jwe`.
    #
    #     !!!ruby
    #     # let's define our jwk and encrypted_key
    #     jwk = JOSE::JWK.from({"k" => "idN_YyeYZqEE7BkpexhA2Q", "kty" => "oct"})
    #     enc = [27,123,126,121,56,105,105,81,140,76,30,2,14,92,231,174,203,196,110,204,57,238,248,73].pack('C*')
    #
    #     JOSE::JWE.key_decrypt(jwk, enc, { "alg" => "A128KW", "enc" => "A128CBC-HS256" })
    #     # => "\x86R\x0F\xB0\xB5s\xAD\x13\r,\xBD\xB9\xBB}\x1C\xF0"
    #
    # @see JOSE::JWE.key_encrypt
    # @param [JOSE::JWK, [JOSE::JWK]] key
    # @param [String] encrypted_key
    # @param [JOSE::JWE] jwe
    # @return [String]
    def self.key_decrypt(key, encrypted_key, jwe)
      return from(jwe).key_decrypt(key, encrypted_key)
    end

    # Decrypts the `encrypted_key` using the `key` and the `"alg"` and `"enc"` specified by the `jwe`.
    #
    # @param [JOSE::JWK, [JOSE::JWK]] key
    # @param [String] encrypted_key
    # @return [String]
    def key_decrypt(key, encrypted_key)
      return alg.key_decrypt(key, enc, encrypted_key)
    end

    # Encrypts the `decrypted_key` using the `key` and the `"alg"` and `"enc"` specified by the `jwe`.
    #
    #    !!!ruby
    #    # let's define our jwk and encrypted_key
    #    jwk = JOSE::JWK.from({"k" => "idN_YyeYZqEE7BkpexhA2Q", "kty" => "oct"})
    #    cek = [134,82,15,176,181,115,173,19,13,44,189,185,187,125,28,240].pack('C*')
    #
    #    JOSE::JWE.key_encrypt(jwk, cek, { "alg" => "A128KW", "enc" => "A128CBC-HS256" })
    #    # => ["\e{~y8iiQ\x8CL\x1E\x02\x0E\\\xE7\xAE\xCB\xC4n\xCC9\xEE\xF8I",
    #    #  #<struct JOSE::JWE
    #    #   alg=#<struct JOSE::JWE::ALG_AES_KW bits=128>,
    #    #   enc=
    #    #    #<struct JOSE::JWE::ENC_AES_CBC_HMAC
    #    #     cipher_name="aes-128-cbc",
    #    #     bits=256,
    #    #     cek_len=32,
    #    #     iv_len=16,
    #    #     enc_len=16,
    #    #     mac_len=16,
    #    #     tag_len=16,
    #    #     hmac=OpenSSL::Digest::SHA256>,
    #    #   zip=nil,
    #    #   fields=JOSE::Map[]>]
    #
    # @see JOSE::JWE.key_decrypt
    # @param [JOSE::JWK, [JOSE::JWK]] key
    # @param [String] decrypted_key
    # @param [JOSE::JWE] jwe
    # @return [[String, JOSE::JWE]]
    def self.key_encrypt(key, decrypted_key, jwe)
      return from(jwe).key_encrypt(key, decrypted_key)
    end

    # Encrypts the `decrypted_key` using the `key` and the `"alg"` and `"enc"` specified by the `jwe`.
    #
    # @param [JOSE::JWK, [JOSE::JWK]] key
    # @param [String] decrypted_key
    # @return [[String, JOSE::JWE]]
    def key_encrypt(key, decrypted_key)
      encrypted_key, new_alg = alg.key_encrypt(key, enc, decrypted_key)
      new_jwe = JOSE::JWE.from_map(to_map)
      new_jwe.alg = new_alg
      return encrypted_key, new_jwe
    end

    # Merges map on right into map on left.
    # @param [JOSE::Map, Hash, String, JOSE::JWE] left
    # @param [JOSE::Map, Hash, String, JOSE::JWE] right
    # @return [JOSE::JWE]
    def self.merge(left, right)
      return from(left).merge(right)
    end

    # Merges object into current map.
    # @param [JOSE::Map, Hash, String, JOSE::JWE] object
    # @return [JOSE::JWE]
    def merge(object)
      object = case object
      when JOSE::Map, Hash
        object
      when String
        JOSE.decode(object)
      when JOSE::JWE
        object.to_map
      else
        raise ArgumentError, "'object' must be a Hash, String, or JOSE::JWE"
      end
      return JOSE::JWE.from_map(self.to_map.merge(object))
    end

    # Returns the next `cek` using the `jwk` and the `"alg"` and `"enc"` specified by the `jwe`.
    #
    #     !!!ruby
    #     # let's define our jwk
    #     jwk = JOSE::JWK.from({"k" => "idN_YyeYZqEE7BkpexhA2Q", "kty" => "oct"}) # JOSE::JWK.generate_key([:oct, 16])
    #
    #     JOSE::JWE.next_cek(jwk, { "alg" => "A128KW", "enc" => "A128CBC-HS256" })
    #     # => ["%S\x8B\xA5,\x17\xA3\xBA\xFF\x9B\xB7\x11\xDC\xD3P\xF7\xEF\x95\xC25\x86)\xFE\xB0\x00\xF7B&\xD9\xFCR\xE9",
    #     #  #<struct JOSE::JWE
    #     #   alg=#<struct JOSE::JWE::ALG_AES_KW bits=128>,
    #     #   enc=
    #     #    #<struct JOSE::JWE::ENC_AES_CBC_HMAC
    #     #     cipher_name="aes-128-cbc",
    #     #     bits=256,
    #     #     cek_len=32,
    #     #     iv_len=16,
    #     #     enc_len=16,
    #     #     mac_len=16,
    #     #     tag_len=16,
    #     #     hmac=OpenSSL::Digest::SHA256>,
    #     #   zip=nil,
    #     #   fields=JOSE::Map[]>]
    #
    #     # when using the "dir" algorithm, the jwk itself will be used
    #     JOSE::JWE.next_cek(jwk, { "alg" => "dir", "enc" => "A128GCM" })
    #     # => ["\x89\xD3\x7Fc'\x98f\xA1\x04\xEC\x19){\x18@\xD9",
    #     #  #<struct JOSE::JWE
    #     #   alg=#<struct JOSE::JWE::ALG_dir direct=true>,
    #     #   enc=#<struct JOSE::JWE::ENC_AES_GCM cipher_name="aes-128-gcm", bits=128, cek_len=16, iv_len=12>,
    #     #   zip=nil,
    #     #   fields=JOSE::Map[]>]
    #
    # @param [JOSE::JWK, [JOSE::JWK, JOSE::JWK]] key
    # @param [JOSE::JWE] jwe
    # @return [[String, JOSE::JWE]]
    def self.next_cek(key, jwe)
      return from(jwe).next_cek(key)
    end

    # Returns the next `cek` using the `jwk` and the `"alg"` and `"enc"` specified by the `jwe`.
    #
    # @param [JOSE::JWK, [JOSE::JWK, JOSE::JWK]] key
    # @return [[String, JOSE::JWE]]
    def next_cek(key)
      decrypted_key, new_alg = alg.next_cek(key, enc)
      new_jwe = JOSE::JWE.from_map(to_map)
      new_jwe.alg = new_alg
      return decrypted_key, new_jwe
    end

    # Returns the next `iv` the `"alg"` and `"enc"` specified by the `jwe`.
    #
    #     !!!ruby
    #     # typically just returns random bytes for the specified "enc" algorithm
    #     JOSE::JWE.next_iv({ "alg" => "dir", "enc" => "A128CBC-HS256" }).bytesize * 8
    #     # => 128
    #     JOSE::JWE.next_iv({ "alg" => "dir", "enc" => "A128GCM" }).bytesize * 8
    #     # => 96
    #
    # @param [JOSE::JWE] jwe
    # @return [String]
    def self.next_iv(jwe)
      return from(jwe).next_iv
    end

    # Returns the next `iv` the `"alg"` and `"enc"` specified by the `jwe`.
    #
    # @return [String]
    def next_iv
      return enc.next_iv
    end

    # Returns the decoded ciphertext portion of a encrypted binary or map without decrypting the ciphertext.
    #
    #     !!!ruby
    #     JOSE::JWE.peek_ciphertext("eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4R0NNIn0.t4_Fb4kCl6BcS1cXnR4P4Xgm-jwVNsFl.RerKfWjzqqtLIUrz.JmE.ZDpVlWo-aQYM5la9eshwWw")
    #     # => "&a"
    #
    # @param [JOSE::EncryptedBinary, String] encrypted
    # @return [String]
    def self.peek_ciphertext(encrypted)
      if encrypted.is_a?(String)
        encrypted = expand(encrypted)
      end
      return JOSE.urlsafe_decode64(encrypted['ciphertext'])
    end

    # Returns the decoded encrypted key portion of a encrypted binary or map without decrypting the ciphertext.
    #
    #     !!!ruby
    #     JOSE::JWE.peek_encrypted_key("eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4R0NNIn0.t4_Fb4kCl6BcS1cXnR4P4Xgm-jwVNsFl.RerKfWjzqqtLIUrz.JmE.ZDpVlWo-aQYM5la9eshwWw")
    #     # => "\xB7\x8F\xC5o\x89\x02\x97\xA0\\KW\x17\x9D\x1E\x0F\xE1x&\xFA<\x156\xC1e"
    #
    # @param [JOSE::EncryptedBinary, String] encrypted
    # @return [String]
    def self.peek_encrypted_key(encrypted)
      if encrypted.is_a?(String)
        encrypted = expand(encrypted)
      end
      return JOSE.urlsafe_decode64(encrypted['encrypted_key'])
    end

    # Returns the decoded initialization vector portion of a encrypted binary or map without decrypting the ciphertext.
    #
    #     !!!ruby
    #     JOSE::JWE.peek_iv("eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4R0NNIn0.t4_Fb4kCl6BcS1cXnR4P4Xgm-jwVNsFl.RerKfWjzqqtLIUrz.JmE.ZDpVlWo-aQYM5la9eshwWw")
    #     # => "E\xEA\xCA}h\xF3\xAA\xABK!J\xF3"
    #
    # @param [JOSE::EncryptedBinary, String] encrypted
    # @return [String]
    def self.peek_iv(encrypted)
      if encrypted.is_a?(String)
        encrypted = expand(encrypted)
      end
      return JOSE.urlsafe_decode64(encrypted['iv'])
    end

    # Returns the decoded protected portion of a encrypted binary or map without decrypting the ciphertext.
    #
    #     !!!ruby
    #     JOSE::JWE.peek_protected("eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4R0NNIn0.t4_Fb4kCl6BcS1cXnR4P4Xgm-jwVNsFl.RerKfWjzqqtLIUrz.JmE.ZDpVlWo-aQYM5la9eshwWw")
    #     # => JOSE::Map["enc" => "A128GCM", "alg" => "A128KW"]
    #
    # @param [JOSE::EncryptedBinary, String] encrypted
    # @return [JOSE::Map]
    def self.peek_protected(encrypted)
      if encrypted.is_a?(String)
        encrypted = expand(encrypted)
      end
      return JOSE::Map.new(JOSE.decode(JOSE.urlsafe_decode64(encrypted['protected'])))
    end

    # Returns the decoded tag portion of a encrypted binary or map without decrypting the ciphertext.
    #
    #     !!!ruby
    #     JOSE::JWE.peek_tag("eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4R0NNIn0.t4_Fb4kCl6BcS1cXnR4P4Xgm-jwVNsFl.RerKfWjzqqtLIUrz.JmE.ZDpVlWo-aQYM5la9eshwWw")
    #     # => "d:U\x95j>i\x06\f\xE6V\xBDz\xC8p["
    #
    # @param [JOSE::EncryptedBinary, String] encrypted
    # @return [String]
    def self.peek_tag(encrypted)
      if encrypted.is_a?(String)
        encrypted = expand(encrypted)
      end
      return JOSE.urlsafe_decode64(encrypted['tag'])
    end

    # Uncompresses the `cipher_text` using the `"zip"` algorithm specified by the `jwe`.
    #
    #     !!!ruby
    #     JOSE::JWE.uncompress([120,156,171,174,5,0,1,117,0,249].pack('C*'), { "alg" => "dir", "zip" => "DEF" })
    #     # => "{}"
    #
    # @see JOSE::JWE.compress
    # @param [String] cipher_text
    # @param [JOSE::JWE] jwe
    # @return [String]
    def self.uncompress(cipher_text, jwe)
      return from(jwe).uncompress(cipher_text)
    end

    # Uncompresses the `cipher_text` using the `"zip"` algorithm specified by the `jwe`.
    #
    # @param [String] cipher_text
    # @return [String]
    def uncompress(cipher_text)
      if zip.nil?
        return cipher_text
      else
        return zip.uncompress(cipher_text)
      end
    end

  private

    def self.from_fields(jwe, modules)
      if jwe.fields.has_key?('alg')
        alg = modules[:alg] || case jwe.fields['alg']
        when 'A128KW', 'A192KW', 'A256KW'
          JOSE::JWE::ALG_AES_KW
        when 'A128GCMKW', 'A192GCMKW', 'A256GCMKW'
          JOSE::JWE::ALG_AES_GCM_KW
        when 'dir'
          JOSE::JWE::ALG_dir
        when 'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW'
          JOSE::JWE::ALG_ECDH_ES
        when 'PBES2-HS256+A128KW', 'PBES2-HS384+A192KW', 'PBES2-HS512+A256KW'
          JOSE::JWE::ALG_PBES2
        when 'RSA1_5', 'RSA-OAEP', 'RSA-OAEP-256'
          JOSE::JWE::ALG_RSA
        else
          raise ArgumentError, "unknown 'alg': #{jwe.fields['alg'].inspect}"
        end
        jwe.alg, jwe.fields = alg.from_map(jwe.fields)
        return from_fields(jwe, modules)
      elsif jwe.fields.has_key?('enc')
        enc = modules[:enc] || case jwe.fields['enc']
        when 'A128CBC-HS256', 'A192CBC-HS384', 'A256CBC-HS512'
          JOSE::JWE::ENC_AES_CBC_HMAC
        when 'A128GCM', 'A192GCM', 'A256GCM'
          JOSE::JWE::ENC_AES_GCM
        else
          raise ArgumentError, "unknown 'enc': #{jwe.fields['enc'].inspect}"
        end
        jwe.enc, jwe.fields = enc.from_map(jwe.fields)
        return from_fields(jwe, modules)
      elsif jwe.fields.has_key?('zip')
        zip = modules[:zip] || case jwe.fields['zip']
        when 'DEF'
          JOSE::JWE::ZIP_DEF
        else
          raise ArgumentError, "unknown 'zip': #{jwe.fields['zip'].inspect}"
        end
        jwe.zip, jwe.fields = zip.from_map(jwe.fields)
        return from_fields(jwe, modules)
      elsif jwe.alg.nil? and jwe.enc.nil?
        raise ArgumentError, "missing required keys: 'alg' and 'enc'"
      else
        return jwe
      end
    end

  end
end

require 'jose/jwe/alg'
require 'jose/jwe/enc'
require 'jose/jwe/zip'
