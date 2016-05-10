require 'test_helper'

class JOSE::JWK::KTY_OKP_Ed448phTest < Minitest::Test

  SECRET_JWK_JSON = "{\"crv\":\"Ed448ph\",\"d\":\"g5TYO57cs-qKL0BCMTNMB6SBKj8ISmigeEmAPEA_Sv3WUeV2U04nM5iMGPHGDbbN_EmlV6vrvHae\",\"kty\":\"OKP\",\"x\":\"mnWhtNStuyGMvLRYqAYJTNu_b2RTiKoF10dJTdkxbyE1wh4TcKfUlOQUkNwbvlKyHvxaEoEuUpgA\"}"
  PUBLIC_JWK_JSON = "{\"crv\":\"Ed448ph\",\"kty\":\"OKP\",\"x\":\"mnWhtNStuyGMvLRYqAYJTNu_b2RTiKoF10dJTdkxbyE1wh4TcKfUlOQUkNwbvlKyHvxaEoEuUpgA\"}"

  def test_generate_key
    jwk_secret = JOSE::JWK.generate_key([:okp, :Ed448ph])
    refute_equal JOSE::JWK.thumbprint(jwk_secret), JOSE::JWK.thumbprint(JOSE::JWK.generate_key(jwk_secret))
  end

  def test_sign_and_verify
    secret_jwk = JOSE::JWK.from_binary(SECRET_JWK_JSON)
    public_jwk = JOSE::JWK.from_binary(PUBLIC_JWK_JSON)
    plain_text = SecureRandom.random_bytes(SecureRandom.random_number(16))
    signed_binary = JOSE::JWK.sign(plain_text, secret_jwk).compact
    verified, payload, = JOSE::JWK.verify(signed_binary, public_jwk)
    assert verified
    assert_equal plain_text, payload
  end

  def test_property_of_sign_and_verify
    skip("Very slow, needs to be implemented in C.")
    property_of {
      Tuple.new([
        gen_jwk_use_sig('Ed448ph'),
        SecureRandom.random_bytes(range(0, size))
      ])
    }.check { |tuple|
      jwk_secret = tuple[0][0]
      jwk_public = tuple[0][1]
      plain_text = tuple[1]
      signed_binary = JOSE::JWK.sign(plain_text, jwk_secret).compact
      verified, payload, = JOSE::JWK.verify(signed_binary, jwk_public)
      assert verified
      assert_equal plain_text, payload
    }
  end

  def test_to_openssh_key_and_from_openssh_key
    secret_jwk = JOSE::JWK.from_binary(SECRET_JWK_JSON)
    assert_equal secret_jwk, JOSE::JWK.from_openssh_key(JOSE::JWK.to_openssh_key(secret_jwk))
  end

  def test_property_of_to_openssh_key_and_from_openssh_key
    skip("Very slow, needs to be implemented in C.")
    property_of {
      gen_jwk_kty_okp(:Ed448ph)
    }.check { |tuple|
      jwk_secret = tuple[0]
      assert_equal jwk_secret, JOSE::JWK.from_openssh_key(JOSE::JWK.to_openssh_key(jwk_secret))
    }
  end

end
