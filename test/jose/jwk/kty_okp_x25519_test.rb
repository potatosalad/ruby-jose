require 'test_helper'

class JOSE::JWK::KTY_OKP_X25519Test < Minitest::Test

  SECRET_JWK_JSON = "{\"crv\":\"X25519\",\"d\":\"OI532y8BG4-umYqGQmupBzg-57lKhhqpLLW53oAp_00\",\"kty\":\"OKP\",\"x\":\"93I7RqdTXgX-FOMPTFwFkNUdBiUoJtKysfbNAYGreFs\"}"
  PUBLIC_JWK_JSON = "{\"crv\":\"X25519\",\"kty\":\"OKP\",\"x\":\"93I7RqdTXgX-FOMPTFwFkNUdBiUoJtKysfbNAYGreFs\"}"
  SECRET_EPK_JSON = "{\"crv\":\"X25519\",\"d\":\"CEjIwWcdyB-vadyLXk6oZtvvtFzPyYBItgQsNH9GiHo\",\"kty\":\"OKP\",\"x\":\"Kq1z0YBxOC5T7BZl6BipGhN7H8apYXYaqHqs702Q1TQ\"}"
  PUBLIC_EPK_JSON = "{\"crv\":\"X25519\",\"kty\":\"OKP\",\"x\":\"Kq1z0YBxOC5T7BZl6BipGhN7H8apYXYaqHqs702Q1TQ\"}"
  SHARED_SECRET   = [18,17,51,28,226,44,56,26,238,5,212,191,218,27,102,223,32,230,177,84,68,239,76,112,137,253,100,82,203,132,76,100].pack('C*')

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
    plain_jwk = JOSE::JWK.generate_key([:okp, :X25519])
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

end
