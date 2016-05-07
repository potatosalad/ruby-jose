## Usage

The simplest combination might be {"alg":"dir","enc":"A128GCM"} which requires a 128-bit (or 16-byte) key that must be fully known by both parties.

```ruby
# Alice wants to send Bob an encrypted message.
# Both Alice and Bob know about the 128-bit key "this is 16 bytes".

# Alice encrypts the plain_text and sends cipher_text to Bob.
plain_text  = "Hello, World!"
jwk         = JOSE::JWK.from_oct("this is 16 bytes")
cipher_text = jwk.block_encrypt(plain_text, {"alg" => "dir", "enc" => "A128GCM"}).compact
# => "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0..oSOfVgfW5dPo4Mwx.x3N6TNI0pTYlBVHiSA.Uu_kROoBRWL0Hb0BH150Zg"

# Bob decrypts the cipher_text using the shared secret key.
cipher_text = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0..oSOfVgfW5dPo4Mwx.x3N6TNI0pTYlBVHiSA.Uu_kROoBRWL0Hb0BH150Zg"
jwk         = JOSE::JWK.from_oct("this is 16 bytes")
plain_text, = jwk.block_decrypt(cipher_text)
# => "Hello, World!"
```

A more complex combination might be `{"alg":"PBES2-HS256+A128KW","enc":"A128GCM","p2c":4096}` which uses a passphrase of any length and generates the Content Encryption Key of the correct length based on that passphrase. The `p2c` in the JSON specifies that 4096 rounds will be done which slows down any brute force attacks trying to determine the passphrase.

```ruby
# Alice wants to send Bob an encrypted message.
# Both Alice and Bob know about the passphrase "alice and bob's secret".

# Alice encrypts the plain_text and sends cipher_text to Bob.
plain_text  = "Hello, World!"
jwk         = JOSE::JWK.from_oct("alice and bob's secret")
cipher_text = jwk.block_encrypt(plain_text, {"alg" => "PBES2-HS256+A128KW", "enc" => "A128GCM", "p2c" => 4096}).compact
# => "eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJlbmMiOiJBMTI4R0NNIiwicDJjIjo0MDk2LCJwMnMiOiJfZEllWDFGX29zUSJ9.B8vGlGGJBNSeGiaOKFJq3MXqhvK5fihL.WUt7m0TldTqW4eNb.wyjPCvfglCovqEd7xw.qZFI-qEV9ACh142xs3MozA"

# Bob decrypts the cipher_text using the shared passphrase.
cipher_text = "eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJlbmMiOiJBMTI4R0NNIiwicDJjIjo0MDk2LCJwMnMiOiJfZEllWDFGX29zUSJ9.B8vGlGGJBNSeGiaOKFJq3MXqhvK5fihL.WUt7m0TldTqW4eNb.wyjPCvfglCovqEd7xw.qZFI-qEV9ACh142xs3MozA"
jwk         = JOSE::JWK.from_oct("alice and bob's secret")
plain_text, = jwk.block_decrypt(cipher_text)
# => "Hello, World!"
```

An even more complex combination might be `{"alg":"ECDH-ES","enc":"A128GCM"}` which requires two sets of keypairs. The sender (in our case Alice) uses their secret key and the public key of the receiver (Bob) to compute a shared key. The public key of the sender is embedded in the resulting encrypted message which the receiver then uses with their own secret key to decrypt the message.

```ruby
# Let's setup the keys that will be used below (use JOSE::JWK.from_binary(...) to load the string version)
## Alice
alice_secret = JOSE::JWK.generate_key([:okp, :X25519])
# => "{\"crv\":\"X25519\",\"d\":\"0Pygq6jZVuWM4lPIhmCCbxtLIsWVzfnK5aM65PC1iX0\",\"kty\":\"OKP\",\"x\":\"uZGRsHIG33ebtKoIBG2WL4_TC_GTZtluSFuOmEPCngc\"}"
alice_public = alice_secret.to_public
# => "{\"crv\":\"X25519\",\"kty\":\"OKP\",\"x\":\"uZGRsHIG33ebtKoIBG2WL4_TC_GTZtluSFuOmEPCngc\"}"
## Bob
bob_secret   = JOSE::JWK.generate_key([:okp, :X25519])
# => "{\"crv\":\"X25519\",\"d\":\"CMVqzIl-pHk0vuAUxhsZccYSLHpJfhRYvz3rTu6R8kc\",\"kty\":\"OKP\",\"x\":\"U-ckTk7roeu-9peZjdhZUIm9yJHtBrrkBJojCpUz5Cs\"}"
bob_public   = bob_secret.to_public
# => "{\"crv\":\"X25519\",\"kty\":\"OKP\",\"x\":\"U-ckTk7roeu-9peZjdhZUIm9yJHtBrrkBJojCpUz5Cs\"}"

# Alice wants to send Bob an encrypted message.
# Bob first sends Alice his public key (bob_public above).

# Alice loads Bob's public key and encrypts the plain_text using her secret key.
# She then sends the resulting cipher_text to Bob.
plain_text  = "Hello, World!"
bob_public  = JOSE::JWK.from_binary("{\"crv\":\"X25519\",\"kty\":\"OKP\",\"x\":\"U-ckTk7roeu-9peZjdhZUIm9yJHtBrrkBJojCpUz5Cs\"}")
cipher_text = bob_public.box_encrypt(plain_text, alice_secret).compact
# => "eyJhbGciOiJFQ0RILUVTIiwiYXB1IjoiZTdwaGd3YU92NXVIVlFkOFJIRFRxcXpMYjZ6T0Nlb1oteXJLRTVmcTM2ayIsImFwdiI6IjY5U1Y3VWo0MWstMEhrcU1GOXVMaEk5Ty14TXZ0UlJ0bU0tbmxJV1RyV2MiLCJlbmMiOiJBMTI4R0NNIiwiZXBrIjp7ImNydiI6IlgyNTUxOSIsImt0eSI6Ik9LUCIsIngiOiJ1WkdSc0hJRzMzZWJ0S29JQkcyV0w0X1RDX0dUWnRsdVNGdU9tRVBDbmdjIn19..EeHOlLmlZocrf0Iz.O2kmN_-6m2YEWiR8XA.CTpSFJKy1GRLU3OoNj_AvA"

# Bob decrypts the cipher_text using his secret key.
cipher_text = "eyJhbGciOiJFQ0RILUVTIiwiYXB1IjoiZTdwaGd3YU92NXVIVlFkOFJIRFRxcXpMYjZ6T0Nlb1oteXJLRTVmcTM2ayIsImFwdiI6IjY5U1Y3VWo0MWstMEhrcU1GOXVMaEk5Ty14TXZ0UlJ0bU0tbmxJV1RyV2MiLCJlbmMiOiJBMTI4R0NNIiwiZXBrIjp7ImNydiI6IlgyNTUxOSIsImt0eSI6Ik9LUCIsIngiOiJ1WkdSc0hJRzMzZWJ0S29JQkcyV0w0X1RDX0dUWnRsdVNGdU9tRVBDbmdjIn19..EeHOlLmlZocrf0Iz.O2kmN_-6m2YEWiR8XA.CTpSFJKy1GRLU3OoNj_AvA"
plain_text, = bob_secret.box_decrypt(cipher_text)
# => "Hello, World!"
```

Here is an example of using X25519 and Ed25519 key pairs to encrypt and then sign a message.

```ruby
# Alice's Signing Key Pair
alice_ed25519_secret = JOSE::JWS.generate_key({"alg" => "Ed25519"})
# => "{\"alg\":\"Ed25519\",\"crv\":\"Ed25519\",\"d\":\"CNnP7HYI-plw66s8GWOJwFCWWCZO1udseqEiyGxJGyk\",\"kty\":\"OKP\",\"use\":\"sig\",\"x\":\"atNiugZnSNxjmd5TM4eXg-aszq7Xarmpsuxrt2yIkUc\"}"
alice_ed25519_public = alice_ed25519_secret.to_public
# => "{\"alg\":\"Ed25519\",\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"use\":\"sig\",\"x\":\"atNiugZnSNxjmd5TM4eXg-aszq7Xarmpsuxrt2yIkUc\"}"

# Bob's Key Agreement Key Pair
bob_x25519_secret    = JOSE::JWK.generate_key([:okp, :X25519])
# => "{\"crv\":\"X25519\",\"d\":\"CMVqzIl-pHk0vuAUxhsZccYSLHpJfhRYvz3rTu6R8kc\",\"kty\":\"OKP\",\"x\":\"U-ckTk7roeu-9peZjdhZUIm9yJHtBrrkBJojCpUz5Cs\"}"
bob_x25519_public    = bob_x25519_secret.to_public
# => "{\"crv\":\"X25519\",\"kty\":\"OKP\",\"x\":\"U-ckTk7roeu-9peZjdhZUIm9yJHtBrrkBJojCpUz5Cs\"}"

# Alice wants to send Bob an encrypted message that has also been signed.
# Alice provides Bob with her public signing key.
# Bob provides Alice with his public key agreement key.
# Alice does not specify her own key agreement key, which results in a new one being generated.
plain_text                       = "Hello, World!"
cipher_text, alice_x25519_secret = bob_x25519_public.box_encrypt(plain_text)
cipher_text                      = cipher_text.compact
# => ["eyJhbGciOiJFQ0RILUVTIiwiYXB1IjoiXy1leGtvYkpFQVpRWi01N1E2ZzRsMHNzbG0yT2I4TnRTeDlwcFFMZEJaNCIsImFwdiI6IjY5U1Y3VWo0MWstMEhrcU1GOXVMaEk5Ty14TXZ0UlJ0bU0tbmxJV1RyV2MiLCJlbmMiOiJBMTI4R0NNIiwiZXBrIjp7ImNydiI6IlgyNTUxOSIsImt0eSI6Ik9LUCIsIngiOiJQR3h4cXRXbnJ2Q0IwOVY0cVRoZEZpUUVweXp6ZVhEMVVJNjYyY0UxNHlrIn19..qcI2uruuJA7wZYda.-NhogJt2ofXlKSZMcQ.7Y9ZBHyPuuSj75u7zR7gpg",
#  "{\"crv\":\"X25519\",\"d\":\"6Gu9vuKL_3YqjBrxLm2rcz3mkKNHMj5pkslVbL7XEVU\",\"kty\":\"OKP\",\"x\":\"PGxxqtWnrvCB09V4qThdFiQEpyzzeXD1UI662cE14yk\"}"]

# Alice then signs the cipher_text using her Ed25519 secret key.
signed_text = alice_ed25519_secret.sign(cipher_text).compact
# => "eyJhbGciOiJFZDI1NTE5In0.ZXlKaGJHY2lPaUpGUTBSSUxVVlRJaXdpWVhCMUlqb2lYeTFsZUd0dllrcEZRVnBSV2kwMU4xRTJaelJzTUhOemJHMHlUMkk0VG5SVGVEbHdjRkZNWkVKYU5DSXNJbUZ3ZGlJNklqWTVVMVkzVldvME1Xc3RNRWhyY1UxR09YVk1hRWs1VHkxNFRYWjBVbEowYlUwdGJteEpWMVJ5VjJNaUxDSmxibU1pT2lKQk1USTRSME5OSWl3aVpYQnJJanA3SW1OeWRpSTZJbGd5TlRVeE9TSXNJbXQwZVNJNklrOUxVQ0lzSW5naU9pSlFSM2g0Y1hSWGJuSjJRMEl3T1ZZMGNWUm9aRVpwVVVWd2VYcDZaVmhFTVZWSk5qWXlZMFV4TkhsckluMTkuLnFjSTJ1cnV1SkE3d1pZZGEuLU5ob2dKdDJvZlhsS1NaTWNRLjdZOVpCSHlQdXVTajc1dTd6UjdncGc.AK5wm7g9UjZflK5Z-0K7SRu8gPiT-zJoz0HBGy1fI9tnpw9_iXReqmsV0Z8NEa34gj4SZbSGYI7KZxXzyZ-VBw"

# Bob receives the signed_text and can immediately verify whether it's from Alice or not.
verified, cipher_text, = alice_ed25519_public.verify(signed_text)
if verified == true
  # Bob can decrypt the cipher_text using his secret X25519 key.
  plain_text, jwe = bob_x25519_secret.box_decrypt(cipher_text)
  # => "Hello, World!"
  # If Bob wanted to send a message back to Alice, he can use the embedded public key to do so:
  jwe.alg.epk.box_encrypt("A message for Alice", bob_x25519_secret)
  # At this point, however, we essentially have a partially functional SSL/TLS implementation.
end
```
