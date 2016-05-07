## Key Generation

Key generation can be done a few different ways, depending on your use case for the key itself.

```ruby
# Using JOSE::JWK.generate_key
# Full control over the parameters for key generation are available when using this method.

## 16-byte oct
JOSE::JWK.generate_key([:oct, 16])
## 2048-bit RSA
JOSE::JWK.generate_key([:rsa, 2048])
## P-521 EC
JOSE::JWK.generate_key([:ec, 'P-521'])
## X25519 OKP
JOSE::JWK.generate_key([:okp, :X25519])

# Using JOSE::JWE.generate_key
# This will generate a JWK that meets the criteria for the "alg" and "enc".
# The special thing about these keys is they have the "use" field set on them.
# So they may only be used for encryption purposes.

## Generates a 16-byte oct
JOSE::JWE.generate_key({"alg" => "dir", "enc" => "A128GCM"})
## Generates a 32-byte oct
JOSE::JWE.generate_key({"alg" => "dir", "enc" => "A256GCM"})
## Generates a 2048-bit RSA key
JOSE::JWE.generate_key({"alg" => "RSA1_5", "enc" => "A128GCM"})
```
