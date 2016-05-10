require 'test_helper'

class JOSE::JWTTest < Minitest::Test

  def test_property_of_from
    property_of {
      urlsafe_base64_dict
    }.check { |object|
      jwt = JOSE::JWT.from(object)
      jwt_binary = JOSE::JWT.to_binary(jwt)
      jwt_map = JOSE::JWT.to_map(jwt)
      assert_equal jwt, JOSE::JWT.from(jwt)
      assert_equal jwt, JOSE::JWT.from(jwt_binary)
      assert_equal jwt, JOSE::JWT.from(jwt_map)
      assert_equal [jwt, jwt, jwt], JOSE::JWT.from([jwt, jwt_binary, jwt_map])
    }
  end

  def test_property_of_encrypt_and_decrypt
    property_of {
      Tuple.new([
        gen_jwk_use_enc(),
        gen_jwt()
      ])
    }.check { |tuple|
      jwk_secret = tuple[0][0]
      jwk_public = tuple[0][1]
      jwt = tuple[1]
      encrypted_map = JOSE::JWT.encrypt(jwk_public, jwt)
      encrypted_binary = JOSE::JWE.compact(encrypted_map)
      decrypted, = JOSE::JWT.decrypt(jwk_secret, encrypted_map)
      assert_equal jwt, decrypted
      decrypted, = JOSE::JWT.decrypt(jwk_secret, encrypted_binary)
      assert_equal jwt, decrypted
    }
  end

  def test_property_of_sign_and_verify
    property_of {
      Tuple.new([
        gen_jwk_use_sig(),
        gen_jwt()
      ])
    }.check { |tuple|
      jwk_secret = tuple[0][0]
      jwk_public = tuple[0][1]
      jwt = tuple[1]
      signed_map = JOSE::JWT.sign(jwk_secret, jwt)
      signed_binary = JOSE::JWS.compact(signed_map)
      verified, payload, = JOSE::JWT.verify(jwk_public, signed_map)
      assert verified
      assert_equal jwt, payload
      verified, payload, = JOSE::JWT.verify(jwk_public, signed_binary)
      assert verified
      assert_equal jwt, payload
    }
  end

end
