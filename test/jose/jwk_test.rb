require 'test_helper'

class JOSE::JWKTest < Minitest::Test

  def test_property_of_from
    property_of {
      gen_jwk()
    }.check { |tuple|
      jwk_secret = tuple[0]
      jwk_public = tuple[1]
      assert_equal jwk_secret, JOSE::JWK.from(JOSE::JWK.to_binary(jwk_secret))
      assert_equal jwk_secret, JOSE::JWK.from(JOSE::JWK.to_map(jwk_secret))
      assert_equal jwk_public, JOSE::JWK.from(JOSE::JWK.to_binary(jwk_public))
      assert_equal jwk_public, JOSE::JWK.from(JOSE::JWK.to_map(jwk_public))
      assert_equal [jwk_secret, jwk_public, jwk_secret, jwk_public], JOSE::JWK.from([JOSE::JWK.to_binary(jwk_secret), JOSE::JWK.to_map(jwk_public), jwk_secret, jwk_public])
    }
  end

end
