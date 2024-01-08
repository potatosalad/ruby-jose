# Changelog

## 1.2.0 (2024-01-08)

* Enhancements
  * Add support for C20P and C20PKW (see [61fb00b](https://github.com/potatosalad/ruby-jose/commit/61fb00b1576225653851fbcb97289306270a14ef) and [2f38f78](https://github.com/potatosalad/ruby-jose/commit/2f38f78996f354b463e8b1208161e9bb7a69437b)).
  * Add support for XC20P and XC20PKW (see [29d0942](https://github.com/potatosalad/ruby-jose/commit/29d09424de720f69050b5f13d3476cb75968c4c5)).
  * Relicense library under MIT license (thanks to [@jessieay](https://github.com/jessieay) in [#14](https://github.com/potatosalad/ruby-jose/pull/14)).

* Fixes
  * Use RSA PSS salt length of hash/digest length instead of max length (thanks to [@abhiuppala](https://github.com/abhiuppala) for reporting in [#12](https://github.com/potatosalad/ruby-jose/issues/12), see [646bdde](https://github.com/potatosalad/ruby-jose/commit/646bdde5a8f7b551056e063a5590c1e822a74b75))
  * Full Ruby 3 and OpenSSL 3 compatibility (thanks to [@beanieboi](https://github.com/beanieboi), see [#25](https://github.com/potatosalad/ruby-jose/pull/25)).

## 1.1.3 (2018-09-20)

* Enhancements
  * Add support for [crypto-rb/ed25519](https://github.com/crypto-rb/ed25519) and [crypto-rb/x25519](https://github.com/crypto-rb/x25519) for curve25519 operations.

* Fixes
  * Support for Ruby 2.5.x RSA keys (thanks to [@waynerobinson](https://github.com/waynerobinson) see [#7](https://github.com/potatosalad/ruby-jose/pull/7))

## 1.1.2 (2016-07-07)

* Enhancements
  * Improved handling of RSA private keys in SMF (Straightforward Method) form to CRT (Chinese Remainder Theorem) form, see [potatosalad/erlang-jose#19](https://github.com/potatosalad/erlang-jose/issues/19)  This is especially useful for keys produced by Java programs using the `RSAPrivateKeySpec` API as mentioned in [Section 9.3 of RFC 7517](https://tools.ietf.org/html/rfc7517#section-9.3).
  * Updated EdDSA operations to comply with draft 04 of [draft-ietf-jose-cfrg-curves-04](https://tools.ietf.org/html/draft-ietf-jose-cfrg-curves-04).

* Fixes
  * Fixed compression encoding bug for `{"zip":"DEF"}` operations (thanks to [@amadden734](https://github.com/amadden734) see [#3](https://github.com/potatosalad/ruby-jose/pull/3))

## 1.1.1 (2016-05-27)

* Enhancements
  * Support for `JOSE::JWK::Set` for key sets.

* Fixes
  * Many of the file writing operations for `JOSE::JWK` have been fixed.

## 1.1.0 (2016-05-10)

* Enhancements
  * Test coverage is now slightly above 90%.
  * Removed legacy support for 32-byte Ed448 and Ed448ph secret keys.
  * Improved behavior of ECDH-ES encryption.

* Fixes
  * X25519 uses RbNaCl when available.
  * Various argument order fixes.

## 1.0.0 (2016-05-07)

* Enhancements
  * [Documentation!](http://www.rubydoc.info/gems/jose) Many thanks to [@soumyaray](https://github.com/soumyaray) for the motivation to improve documentation.
  * Support for OpenSSH octet key pairs (for Ed25519).
  * Better key management behavior associated with ECDH-ES algorithms.

## 0.3.1 (2016-05-05)

* Fixes
  * Fix bug with PBES2 based encryption.

## 0.3.0 (2016-05-05)

* Enhancements
  * Added merge functions:
    * `JOSE::JWE#merge`
    * `JOSE::JWK#merge`
    * `JOSE::JWS#merge`
    * `JOSE::JWT#merge`
  * Added block_encryptor and signer functions:
    * `JOSE::JWK#block_encryptor`
    * `JOSE::JWK#signer`
  * Support for `"alg"`, `"enc"`, and `"use"` on keys.

Examples of new functionality:

```ruby
# Let's generate a 64 byte octet key
jwk = JOSE::JWK.generate_key([:oct, 64])
# => {"k"=>"FXSy7PufOayusvfyKQzdxCegm7yWIMp1b0LD13v57Nq2wF_B-fcr7LDOkufDikmFFsVYWLgrA2zEB--_qqDn3g", "kty"=>"oct"}

# Based on the key's size and type, a default signer (JWS) can be determined
jwk.signer
# => {"alg"=>"HS512"}

# Based on the key's size and type, a default encryptor (JWE) can be determined
jwk.block_encryptor
# => {"alg"=>"dir", "enc"=>"A256CBC-HS512"}

# Keys can be generated based on the signing algorithm (JWS)
JOSE::JWS.generate_key({'alg' => 'HS256'})
# => {"alg"=>"HS256", "k"=>"UuP3Tw2xbGV5N3BGh34cJNzzC2R1zU7i4rOnF9A8nqY", "kty"=>"oct", "use"=>"sig"}

# Keys can be generated based on the encryption algorithm (JWE)
JOSE::JWE.generate_key({'alg' => 'dir', 'enc' => 'A128GCM'})
# => {"alg"=>"dir", "enc"=>"A128GCM", "k"=>"8WNdBjXXwg6QTwrrOnvEPw", "kty"=>"oct", "use"=>"enc"}

# Example of merging a map into an existing JWS (also works with JWE, JWK, and JWT)
jws = JOSE::JWS.from({'alg' => 'HS256'})
jws.merge({'typ' => 'JWT'})
# => {"alg"=>"HS256", "typ"=>"JWT"}
```

## 0.2.0 (2016-02-25)

* Enhancements
  * Add `JOSE.__crypto_fallback__` which can be set directly or with the `JOSE_CRYPTO_FALLBACK` environment variable.  EdDSA and EdDH algorithms not natively supported are disabled by default.
  * Support [OKP](https://tools.ietf.org/html/draft-ietf-jose-cfrg-curves) key type with the following curves:
    * `Ed25519` (external [RbNaCl](https://github.com/cryptosphere/rbnacl) or fallback supported)
    * `Ed25519ph` (external [RbNaCl](https://github.com/cryptosphere/rbnacl) or fallback supported)
    * `X25519` (external [RbNaCl](https://github.com/cryptosphere/rbnacl) or fallback supported)
    * `Ed448` (no external, but fallback supported)
    * `Ed448ph` (no external, but fallback supported)
    * `X448` (no external, but fallback supported)
  * Support [SHA-3](https://en.wikipedia.org/wiki/SHA-3) functions for use with `Ed448` and `Ed448ph`.
  * Add `JOSE::JWK#shared_secret` for computing the shared secret between two `EC` or `OKP` keys.

## 0.1.0 (2015-11-24)

* Initial Release

* Algorithm Support
  * JSON Web Encryption (JWE) [RFC 7516](https://tools.ietf.org/html/rfc7516)
    * `"alg"` [RFC 7518 Section 4](https://tools.ietf.org/html/rfc7518#section-4)
      * `RSA1_5`
      * `RSA-OAEP`
      * `RSA-OAEP-256`
      * `A128KW`
      * `A192KW`
      * `A256KW`
      * `dir`
      * `ECDH-ES`
      * `ECDH-ES+A128KW`
      * `ECDH-ES+A192KW`
      * `ECDH-ES+A256KW`
      * `A128GCMKW`
      * `A192GCMKW`
      * `A256GCMKW`
      * `PBES2-HS256+A128KW`
      * `PBES2-HS384+A192KW`
      * `PBES2-HS512+A256KW`
    * `"enc"` [RFC 7518 Section 5](https://tools.ietf.org/html/rfc7518#section-5)
      * `A128CBC-HS256`
      * `A192CBC-HS384`
      * `A256CBC-HS512`
      * `A128GCM`
      * `A192GCM`
      * `A256GCM`
    * `"zip"` [RFC 7518 Section 7.3](https://tools.ietf.org/html/rfc7518#section-7.3)
      * `DEF`
  * JSON Web Key (JWK) [RFC 7517](https://tools.ietf.org/html/rfc7517)
    * `"alg"` [RFC 7518 Section 6](https://tools.ietf.org/html/rfc7518#section-6)
      * `EC`
      * `RSA`
      * `oct`
  * JSON Web Signature (JWS) [RFC 7515](https://tools.ietf.org/html/rfc7515)
    * `"alg"` [RFC 7518 Section 3](https://tools.ietf.org/html/rfc7518#section-3)
      * `HS256`
      * `HS384`
      * `HS512`
      * `RS256`
      * `RS384`
      * `RS512`
      * `ES256`
      * `ES384`
      * `ES512`
      * `PS256`
      * `PS384`
      * `PS512`
      * `none`
