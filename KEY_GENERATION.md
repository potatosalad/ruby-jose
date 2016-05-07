# Examples: Key Generation

There are four key generation methods described below for each key type:

* Method 1: OpenSSL
* Method 2: `JOSE::JWK.generate_key`
* Method 3: `JOSE::JWE.generate_key`
* Method 4: `JOSE::JWS.generate_key`

## EC

The three curve types defined in the [JWA RFC 7518](https://tools.ietf.org/html/rfc7518#section-6.2.1.1) for the `EC` key type are:

1. `"P-256"` (openssl curve `secp256r1`)
2. `"P-384"` (openssl curve `secp384r1`)
3. `"P-521"` (openssl curve `secp521r1`)

### Method 1

The basic formula for key generation is `openssl ecparam -name CURVE -genkey -noout -out FILE`, for example:

```bash
openssl ecparam -name secp256r1 -genkey -noout -out ec-secp256r1.pem
openssl ecparam -name secp384r1 -genkey -noout -out ec-secp384r1.pem
openssl ecparam -name secp521r1 -genkey -noout -out ec-secp521r1.pem
```

The PEM files can then be read using `JOSE::JWK.from_pem_file`:

```ruby
jwk = JOSE::JWK.from_pem_file("ec-secp256r1.pem")
```

### Method 2

The curve names are almost the same as the ones for OpenSSL.

```ruby
jwk = JOSE::JWK.generate_key([:ec, 'prime256v1'])
jwk = JOSE::JWK.generate_key([:ec, 'secp384r1'])
jwk = JOSE::JWK.generate_key([:ec, 'secp521r1'])

# Alternative curve alias syntax:
jwk = JOSE::JWK.generate_key([:ec, 'P-256'])
jwk = JOSE::JWK.generate_key([:ec, 'P-384'])
jwk = JOSE::JWK.generate_key([:ec, 'P-521'])
```

Keys may also be generated based on other keys.  The new key will use the same curve as the supplied key.

```ruby
old_jwk = JOSE::JWK.from_pem_file("ec-secp256r1.pem")
new_jwk = JOSE::JWK.generate_key(old_jwk)
```

### Method 3

If you have a JWE header with an `"epk"` field, a new key will be generated based on the same key type of the `"epk"`.  Otherwise, the `P-521` curve will be used.

```ruby
# Based on the "epk" field.
epk = JOSE::JWK.generate_key([:ec, 'P-256'])
jwe = JOSE::JWE.from_map({"alg" => "ECDH-ES", "enc" => "A128GCM", "epk" => epk.to_map})
jwk = jwe.generate_key

# Otherwise, defaults to "P-521".
jwk = JOSE::JWE.generate_key({"alg" => "ECDH-ES", "enc" => "A128GCM"})
```

### Method 4

If you have a JWS header with one of the ECDSA signature algorithms specified, a corresponding EC key will be generated with the correct curve for the signature type.

```ruby
jwk_ec256 = JOSE::JWS.generate_key({"alg" => "ES256"})
jwk_ec384 = JOSE::JWS.generate_key({"alg" => "ES384"})
jwk_ec521 = JOSE::JWS.generate_key({"alg" => "ES512"})
```

## oct

This key type is simply an octet or byte sequence (see [RFC 7518 Section 6.4](https://tools.ietf.org/html/rfc7518#section-6.4)).

### Method 1

The basic formula for generating a random octet sequence is `openssl rand -out FILE BYTE_SIZE`, for example:

```bash
openssl rand -out oct-128-bit.bin 16
```

The binary file can then be read using `JOSE::JWK.from_oct_file`:

```ruby
jwk = JOSE::JWK.from_oct_file("oct-128-bit.bin")
```

### Method 2

Calling either of these functions with an integer will generate a random octet sequence.

```ruby
jwk = JOSE::JWK.generate_key([:oct, 16])
```

Keys may also be generated based on other keys.  The new key will use the same byte size as the supplied key.

```ruby
old_jwk = JOSE::JWK.from_oct_file("oct-128-bit.bin")
new_jwk = JOSE::JWK.generate_key(old_jwk)
```

### Method 3

If you have a JWE header with an `"alg"` field that requires a symmetric key, a new `oct` key will be generated based on the byte size required of `"alg"` and/or `"enc"`.

```ruby
jwk_oct16 = JOSE::JWE.generate_key({"alg" => "dir", "enc" => "A128GCM"})
jwk_oct24 = JOSE::JWE.generate_key({"alg" => "dir", "enc" => "A192GCM"})
jwk_oct32 = JOSE::JWE.generate_key({"alg" => "dir", "enc" => "A256GCM"})
jwk_oct32 = JOSE::JWE.generate_key({"alg" => "dir", "enc" => "A128CBC-HS256"})
jwk_oct48 = JOSE::JWE.generate_key({"alg" => "dir", "enc" => "A192CBC-HS384"})
jwk_oct64 = JOSE::JWE.generate_key({"alg" => "dir", "enc" => "A256CBC-HS512"})
```

### Method 4

If you have a JWS header with an `"alg"` field that requires a symmetric key, a new `oct` key will be generated based on the byte size recommended for `"alg".

```ruby
jwk_oct32 = JOSE::JWS.generate_key({"alg" => "HS256"})
jwk_oct48 = JOSE::JWS.generate_key({"alg" => "HS384"})
jwk_oct64 = JOSE::JWS.generate_key({"alg" => "HS512"})
```

## OKP

This key type is an octet key pair with an associated curve (see [draft-ietf-jose-cfrg-curves](https://tools.ietf.org/html/draft-ietf-jose-cfrg-curves)).

### Method 1

*NOTE:* Only `Ed25519` is currently supported by `ssh-keygen`.

The basic formula for generating a octet key pair is `ssh-keygen -t TYPE -f FILE`, for example:

```bash
ssh-keygen -t ed25519 -f ed25519
```

The private key file can then be read using `JOSE::JWK.from_openssh_key_file`:

```ruby
jwk = JOSE::JWK.from_openssh_key_file("ed25519")
```

### Method 2

Calling either of these functions with a specified curve will generate an octet key pair.  You may also specify the secret portion of the key after the curve.

```ruby
% Curve25519
jwk_Ed25519   = JOSE::JWK.generate_key([:okp, :Ed25519])
jwk_Ed25519ph = JOSE::JWK.generate_key([:okp, :Ed25519ph])
jwk_X25519    = JOSE::JWK.generate_key([:okp, :X25519])

% Curve448
jwk_Ed448   = JOSE::JWK.generate_key([:okp, :Ed448])
jwk_Ed448ph = JOSE::JWK.generate_key([:okp, :Ed448ph])
jwk_X448    = JOSE::JWK.generate_key([:okp, :X448])
```

Keys may also be generated based on other keys.  The new key will use the same curve as the supplied key.

```ruby
old_jwk = JOSE::JWK.from_openssh_key_file("ed25519")
new_jwk = JOSE::JWK.generate_key(old_jwk)
```

### Method 3

If you have a JWE header with an `"epk"` field, a new key will be generated based on the same key type of the `"epk"`.

```ruby
# Based on the "epk" field.
epk = JOSE::JWK.generate_key([:okp, :X25519])
jwe = JOSE::JWE.from_map({"alg" => "ECDH-ES", "enc" => "A128GCM", "epk" => epk.to_map})
jwk = jwe.generate_key
```

### Method 4

If you have a JWS header with one of the EdDSA signature algorithms specified, a corresponding OKP key will be generated with the correct curve for the signature type.

```ruby
jwk_Ed25519   = JOSE::JWS.generate_key({"alg" => "Ed25519"})
jwk_Ed25519ph = JOSE::JWS.generate_key({"alg" => "Ed25519ph"})
jwk_Ed448     = JOSE::JWS.generate_key({"alg" => "Ed448"})
jwk_Ed448ph   = JOSE::JWS.generate_key({"alg" => "Ed448ph"})
```

## RSA

Both two-prime and multi-prime RSA keys are supported by [RFC 7518 Section 6.3](https://tools.ietf.org/html/rfc7518#section-6.3), but currently only two-prime RSA keys can be generated by OpenSSL-based generators.  Ruby does not support multi-prime RSA at this time.

### Method 1

The basic formula for generating a RSA key is `openssl genrsa -out FILE BIT_SIZE`, for example:

```bash
openssl genrsa -out rsa-2048.pem 2048
```

The PEM file can then be read using `JOSE::JWK.from_pem_file`:

```ruby
jwk = JOSE::JWK.from_pem_file("rsa-2048.pem")
```

### Method 2

The modulus bit size is the only required argument.  Optionally, you may specify the public exponent as the second argument (default is `65537`).

```ruby
jwk = JOSE::JWK.generate_key([:rsa, 2048])

# Alternative explicit syntax with public exponent:
jwk = JOSE::JWK.generate_key([:rsa, 4096, 65537])
```

Keys may also be generated based on other keys.  The new key will use the same modulus size and public exponent as the supplied key.

```ruby
old_jwk = JOSE::JWK.from_pem_file("rsa-2048.pem")
new_jwk = JOSE::JWK.generate_key(old_jwk)
```

### Method 3

If you have a JWE header with an `"alg"` field that requires an asymmetric RSA key, a new `RSA` key will be generated. 2048-bit keys are generated in these cases.

```ruby
jwk_rsa1_5      = JOSE::JWE.generate_key({"alg" => "RSA1_5", "enc" => "A128GCM"})
jwk_rsa_oaep    = JOSE::JWE.generate_key({"alg" => "RSA-OAEP", "enc" => "A128GCM"})
jwk_rsa_oaep256 = JOSE::JWE.generate_key({"alg" => "RSA-OAEP-256", "enc" => "A128GCM"})
```

### Method 4

If you have a JWS header with one of the RSA PKCS1 or PSS signature algorithms specified, a corresponding RSA key will be generated with a recommended modulus size based on the digest type.

```ruby
# RS256, RS384, RS512
jwk_rsa2048 = JOSE::JWS.generate_key({"alg" => "RS256"})
jwk_rsa3072 = JOSE::JWS.generate_key({"alg" => "RS384"})
jwk_rsa4096 = JOSE::JWS.generate_key({"alg" => "RS512"})

# PS256, PS384, PS512
jwk_rsa2048 = JOSE::JWS.generate_key({"alg" => "PS256"})
jwk_rsa3072 = JOSE::JWS.generate_key({"alg" => "PS384"})
jwk_rsa4096 = JOSE::JWS.generate_key({"alg" => "PS512"})
```
