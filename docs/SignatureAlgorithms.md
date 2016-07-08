# @title Signature Algorithms

# Signature Algorithms

The basic parameters for a {JOSE::JWS JOSE::JWS} header are:

- `"alg"` **(required)** - Cryptographic Algorithm used to secure the JWS.

See [RFC 7515](https://tools.ietf.org/html/rfc7515#section-4.1) for more information about other header parameters.

### `alg` Header Parameter

Here are the supported options for the `alg` parameter, grouped by similar funcionality:

- Elliptic Curve Digital Signature Algorithm (ECDSA)
  - [`ES256`](http://www.rubydoc.info/gems/jose/JOSE/JWS#ECDSA-group)
  - [`ES384`](http://www.rubydoc.info/gems/jose/JOSE/JWS#ECDSA-group)
  - [`ES512`](http://www.rubydoc.info/gems/jose/JOSE/JWS#ECDSA-group)
- Edwards-curve Digital Signature Algorithm (EdDSA)
  - [`Ed25519`](http://www.rubydoc.info/gems/jose/JOSE/JWS#EdDSA-25519-group)
  - [`Ed25519ph`](http://www.rubydoc.info/gems/jose/JOSE/JWS#EdDSA-25519-group)
  - [`Ed448`](http://www.rubydoc.info/gems/jose/JOSE/JWS#EdDSA-448-group)
  - [`Ed448ph`](http://www.rubydoc.info/gems/jose/JOSE/JWS#EdDSA-448-group)
  - [`EdDSA`](http://www.rubydoc.info/gems/jose/JOSE/JWS#EdDSA-group)
- HMAC using SHA-2
  - [`HS256`](http://www.rubydoc.info/gems/jose/JOSE/JWS#HMACSHA2-group)
  - [`HS384`](http://www.rubydoc.info/gems/jose/JOSE/JWS#HMACSHA2-group)
  - [`HS512`](http://www.rubydoc.info/gems/jose/JOSE/JWS#HMACSHA2-group)
- RSASSA PSS using SHA-2 and MGF1 with SHA-2
  - [`PS256`](http://www.rubydoc.info/gems/jose/JOSE/JWS#RSASSAPSS-group)
  - [`PS384`](http://www.rubydoc.info/gems/jose/JOSE/JWS#RSASSAPSS-group)
  - [`PS512`](http://www.rubydoc.info/gems/jose/JOSE/JWS#RSASSAPSS-group)
- RSASSA PKCS#1.5 using SHA-2
  - [`RS256`](http://www.rubydoc.info/gems/jose/JOSE/JWS#RSASSAPKCS1_5-group)
  - [`RS384`](http://www.rubydoc.info/gems/jose/JOSE/JWS#RSASSAPKCS1_5-group)
  - [`RS512`](http://www.rubydoc.info/gems/jose/JOSE/JWS#RSASSAPKCS1_5-group)
