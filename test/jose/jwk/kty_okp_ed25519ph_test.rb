require 'test_helper'

class JOSE::JWK::KTY_OKP_Ed25519phTest < Minitest::Test

  def test_generate_key
    jwk_secret = JOSE::JWK.generate_key([:okp, :Ed25519ph])
    refute_equal JOSE::JWK.thumbprint(jwk_secret), JOSE::JWK.thumbprint(JOSE::JWK.generate_key(jwk_secret))
  end

  def test_property_of_sign_and_verify
    property_of {
      Tuple.new([
        gen_jwk_use_sig('Ed25519ph'),
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

  def test_property_of_to_openssh_key_and_from_openssh_key
    property_of {
      gen_jwk_kty_okp(:Ed25519ph)
    }.check { |tuple|
      jwk_secret = tuple[0]
      assert_equal jwk_secret, JOSE::JWK.from_openssh_key(JOSE::JWK.to_openssh_key(jwk_secret))
    }
  end

end
