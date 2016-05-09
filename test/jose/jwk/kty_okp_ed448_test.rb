require 'test_helper'

class JOSE::JWK::KTY_OKP_Ed448Test < Minitest::Test

  def test_property_of_sign_and_verify
    property_of {
      Tuple.new([
        gen_jwk_use_sig('Ed448'),
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

end
