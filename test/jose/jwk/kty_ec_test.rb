require 'test_helper'

class JOSE::JWK::KTY_OKP_ECTest < Minitest::Test

  SECRET_JWK_JSON = "{\"crv\":\"P-256\",\"d\":\"8JrNI9OsOICTQ-AvjrqaKcLTpqzvTSzDzaTPEIgfSlQ\",\"kty\":\"EC\",\"x\":\"sc4IAHTm5VXohRMrwfDHp43xD3FndACOL-T-dNVxIB0\",\"y\":\"d3UCc6S4Zl_7Ngfx7OmMtF1WFVQflmTOE6T5Xg7mnLw\"}"
  PUBLIC_JWK_JSON = "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"sc4IAHTm5VXohRMrwfDHp43xD3FndACOL-T-dNVxIB0\",\"y\":\"d3UCc6S4Zl_7Ngfx7OmMtF1WFVQflmTOE6T5Xg7mnLw\"}"
  SECRET_EPK_JSON = "{\"crv\":\"P-256\",\"d\":\"zWN7--gWPzBWw0TMJlU5Vircjkk_RKJTl9NVDpLvwk4\",\"kty\":\"EC\",\"x\":\"ACiE6kNmjcATszoFzvacvj3UQ1OA5wJOTmKAZE6RRoQ\",\"y\":\"Tgnxw82hFJl968ALk5rgROxjfgUY7z4k4SY7t0gfdII\"}"
  PUBLIC_EPK_JSON = "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"ACiE6kNmjcATszoFzvacvj3UQ1OA5wJOTmKAZE6RRoQ\",\"y\":\"Tgnxw82hFJl968ALk5rgROxjfgUY7z4k4SY7t0gfdII\"}"
  SHARED_SECRET   = [227,91,164,154,84,202,40,57,45,214,16,63,15,2,252,73,41,118,240,14,56,101,12,66,84,41,99,224,48,131,11,210].pack('C*')

  def test_from_binary_and_to_binary
    secret_jwk = JOSE::JWK.from_binary(SECRET_JWK_JSON)
    public_jwk = JOSE::JWK.from_binary(PUBLIC_JWK_JSON)
    assert_equal SECRET_JWK_JSON, JOSE::JWK.to_binary(secret_jwk)
    assert_equal PUBLIC_JWK_JSON, JOSE::JWK.to_binary(public_jwk)
    assert_equal public_jwk,      JOSE::JWK.to_public(secret_jwk)
  end

  def test_shared_secret
    secret_jwk = JOSE::JWK.from_binary(SECRET_JWK_JSON)
    public_jwk = JOSE::JWK.from_binary(PUBLIC_JWK_JSON)
    secret_epk = JOSE::JWK.from_binary(SECRET_EPK_JSON)
    public_epk = JOSE::JWK.from_binary(PUBLIC_EPK_JSON)
    assert_equal SHARED_SECRET, JOSE::JWK.shared_secret(public_jwk, secret_epk)
    assert_equal SHARED_SECRET, JOSE::JWK.shared_secret(public_epk, secret_jwk)
  end

  def test_block_encryptor
    plain_jwk = JOSE::JWK.generate_key([:ec, 'P-256'])
    assert_equal JOSE::Map['alg' => 'ECDH-ES', 'enc' => 'A128GCM'], JOSE::JWK.block_encryptor(plain_jwk)
    apu = SecureRandom.urlsafe_base64(8)
    apv = SecureRandom.urlsafe_base64(8)
    epk = plain_jwk.to_public.to_map
    extra_jwk = plain_jwk.merge({
      'alg' => 'ECDH-ES',
      'apu' => apu,
      'apv' => apv,
      'enc' => 'A128GCM',
      'epk' => epk,
      'use' => 'enc'
    })
    assert_equal(JOSE::Map[
      'alg' => 'ECDH-ES',
      'apu' => apu,
      'apv' => apv,
      'enc' => 'A128GCM',
      'epk' => epk
    ], JOSE::JWK.block_encryptor(extra_jwk))
  end

  def test_signer
    ec_p256_jwk = JOSE::JWK.generate_key([:ec, 'P-256'])
    ec_p384_jwk = JOSE::JWK.generate_key([:ec, 'P-384'])
    ec_p521_jwk = JOSE::JWK.generate_key([:ec, 'P-521'])
    assert_equal JOSE::Map['alg' => 'ES256'], JOSE::JWK.signer(ec_p256_jwk)
    assert_equal JOSE::Map['alg' => 'ES384'], JOSE::JWK.signer(ec_p384_jwk)
    assert_equal JOSE::Map['alg' => 'ES512'], JOSE::JWK.signer(ec_p521_jwk)
    extra_ec_p256_jwk = ec_p256_jwk.merge({'alg' => 'ES256', 'use' => 'sig'})
    assert_equal JOSE::Map['alg' => 'ES256'], JOSE::JWK.signer(extra_ec_p256_jwk)
    public_ec_p256_jwk = JOSE::JWK.to_public(ec_p256_jwk)
    assert_raises(ArgumentError) { JOSE::JWK.signer(public_ec_p256_jwk) }
  end

  def test_verifier
    ec_p256_jwk = JOSE::JWK.generate_key([:ec, 'P-256'])
    ec_p384_jwk = JOSE::JWK.generate_key([:ec, 'P-384'])
    ec_p521_jwk = JOSE::JWK.generate_key([:ec, 'P-521'])
    assert_equal ['ES256'], JOSE::JWK.verifier(ec_p256_jwk)
    assert_equal ['ES384'], JOSE::JWK.verifier(ec_p384_jwk)
    assert_equal ['ES512'], JOSE::JWK.verifier(ec_p521_jwk)
    extra_ec_p256_jwk = ec_p256_jwk.merge({'alg' => 'ES256', 'use' => 'sig'})
    assert_equal ['ES256'], JOSE::JWK.verifier(extra_ec_p256_jwk)
  end

  def test_key_encryptor
    secret_jwk = JOSE::JWK.from_binary(SECRET_JWK_JSON)
    key_encryptor = secret_jwk.kty.key_encryptor(secret_jwk.fields, 'test')
    assert_equal 'PBES2-HS256+A128KW', key_encryptor['alg']
  end

end
