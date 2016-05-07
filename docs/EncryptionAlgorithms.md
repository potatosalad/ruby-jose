# @title Encryption Algorithms

# Encryption Algorithms

The basic parameters for a {JOSE::JWE JOSE::JWE} header are:

- `"alg"` **(required)** - Key Management Algorithm used to encrypt or determine the value of the Content Encryption Key.
- `"enc"` **(required)** - Encryption Algorithm used to perform authenticated encryption on the plain text using the Content Encryption Key.
- `"zip"` *(optional)* - Compression Algorithm applied to the plaintext before encryption, if any.

See [RFC 7516](https://tools.ietf.org/html/rfc7516#section-4.1) for more information about other header parameters.

### `alg` Header Parameter

Here are the supported options for the `alg` parameter, grouped by similar funcionality:

- Single Asymmetric Public/Private Key Pair
  - [`RSA1_5`](http://www.rubydoc.info/gems/jose/JOSE/JWE#RSA-group)
  - [`RSA-OAEP`](http://www.rubydoc.info/gems/jose/JOSE/JWE#RSA-group)
  - [`RSA-OAEP-256`](http://www.rubydoc.info/gems/jose/JOSE/JWE#RSA-group)
- Two Asymmetric Public/Private Key Pairs with Key Agreement
  - [`ECDH-ES`](http://www.rubydoc.info/gems/jose/JOSE/JWE#ECDH-ES-group)
  - [`ECDH-ES+A128KW`](http://www.rubydoc.info/gems/jose/JOSE/JWE#ECDH-ES-group)
  - [`ECDH-ES+A192KW`](http://www.rubydoc.info/gems/jose/JOSE/JWE#ECDH-ES-group)
  - [`ECDH-ES+A256KW`](http://www.rubydoc.info/gems/jose/JOSE/JWE#ECDH-ES-group)
- Symmetric Password Based Key Derivation
  - [`PBES2-HS256+A128KW`](http://www.rubydoc.info/gems/jose/JOSE/JWE#PBES2-group)
  - [`PBES2-HS384+A192KW`](http://www.rubydoc.info/gems/jose/JOSE/JWE#PBES2-group)
  - [`PBES2-HS512+A256KW`](http://www.rubydoc.info/gems/jose/JOSE/JWE#PBES2-group)
- Symmetric Key Wrap
  - [`A128GCMKW`](http://www.rubydoc.info/gems/jose/JOSE/JWE#AESGCMKW-group)
  - [`A192GCMKW`](http://www.rubydoc.info/gems/jose/JOSE/JWE#AESGCMKW-group)
  - [`A256GCMKW`](http://www.rubydoc.info/gems/jose/JOSE/JWE#AESGCMKW-group)
  - [`A128KW`](http://www.rubydoc.info/gems/jose/JOSE/JWE#AESKW-group)
  - [`A192KW`](http://www.rubydoc.info/gems/jose/JOSE/JWE#AESKW-group)
  - [`A256KW`](http://www.rubydoc.info/gems/jose/JOSE/JWE#AESKW-group)
- Symmetric Direct Key (known to both sides)
  - [`dir`](http://www.rubydoc.info/gems/jose/JOSE/JWE#direct-group)

### `enc` Header Parameter

Here are the options for the `enc` parameter:

- [`A128CBC-HS256`](http://www.rubydoc.info/gems/jose/JOSE/JWE#AESCBC-group)
- [`A192CBC-HS384`](http://www.rubydoc.info/gems/jose/JOSE/JWE#AESCBC-group)
- [`A256CBC-HS512`](http://www.rubydoc.info/gems/jose/JOSE/JWE#AESCBC-group)
- [`A128GCM`](http://www.rubydoc.info/gems/jose/JOSE/JWE#AESGCM-group)
- [`A192GCM`](http://www.rubydoc.info/gems/jose/JOSE/JWE#AESGCM-group)
- [`A256GCM`](http://www.rubydoc.info/gems/jose/JOSE/JWE#AESGCM-group)

### `zip` Header Parameter

Here are the options for the `zip` parameter:

- [`DEF`](http://www.rubydoc.info/gems/jose/JOSE/JWE#DEF-group)
