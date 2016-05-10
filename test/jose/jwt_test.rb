require 'test_helper'

class JOSE::JWTTest < Minitest::Test

  def test_property_of_from
    property_of {
      urlsafe_base64_dict()
    }.check { |object|
      jwt = JOSE::JWT.from(object)
      jwt_binary = JOSE::JWT.to_binary(jwt)
      jwt_map = JOSE::JWT.to_map(jwt)
      assert_equal jwt, JOSE::JWT.from(jwt)
      assert_equal jwt, JOSE::JWT.from(jwt_binary)
      assert_equal jwt, JOSE::JWT.from(jwt_map)
      assert_equal [jwt, jwt, jwt], JOSE::JWT.from([jwt, jwt_binary, jwt_map])
      jwt_binary_array = JOSE::JWT.to_binary([jwt])
      jwt_map_array = JOSE::JWT.to_map([jwt])
      assert_equal [jwt], JOSE::JWT.from_binary(jwt_binary_array)
      assert_equal [jwt], JOSE::JWT.from_map(jwt_map_array)
      assert_raises(ArgumentError) { JOSE::JWT.from(nil) }
      assert_raises(ArgumentError) { JOSE::JWT.from_binary(nil) }
      assert_raises(ArgumentError) { JOSE::JWT.from_map(nil) }
    }
  end

  def test_merge
    unmerged_jwt = JOSE::JWT.from({'a' => '1', 'b' => '1'})
    binary = "{\"b\":\"2\",\"c\":\"3\"}"
    map = JOSE::Map['b' => '2', 'c' => '3']
    jwt = JOSE::JWT.from(map)
    merged_jwt = JOSE::JWT.from({'a' => '1', 'b' => '2', 'c' => '3'})
    assert_equal merged_jwt, JOSE::JWT.merge(unmerged_jwt, binary)
    assert_equal merged_jwt, JOSE::JWT.merge(unmerged_jwt, map)
    assert_equal merged_jwt, JOSE::JWT.merge(unmerged_jwt, jwt)
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

  def test_sign_and_verify_strict
    jwk = JOSE::JWK.generate_key([:oct, 64])
    jwt = JOSE::JWT.from({'a' => '1', 'b' => '2', 'c' => '3'})
    jws = JOSE::JWS.from({'alg' => 'HS512'})
    signed_map = JOSE::JWT.sign(jwk, jws, jwt)
    signed_binary = signed_map.compact
    # Verify explicit
    verified, payload, = JOSE::JWT.verify_strict(jwk, ['HS512'], signed_map)
    assert verified
    assert_equal jwt, payload
    verified, payload, = JOSE::JWT.verify_strict(jwk, ['HS512'], signed_binary)
    assert verified
    assert_equal jwt, payload
    # Verify implicit
    verifiers = JOSE::JWK.verifier(jwk)
    verified, payload, = JOSE::JWT.verify_strict(jwk, verifiers, signed_map)
    assert verified
    assert_equal jwt, payload
    verified, payload, = JOSE::JWT.verify_strict(jwk, verifiers, signed_binary)
    assert verified
    assert_equal jwt, payload
    # Fail verification
    verified, payload, = JOSE::JWT.verify_strict(jwk, ['HS256', 'HS384'], signed_map)
    refute verified
    refute_equal jwt, payload
    verified, payload, = JOSE::JWT.verify_strict(jwk, ['HS256', 'HS384'], signed_binary)
    refute verified
    refute_equal jwt, payload
  end

  SIGNED_BINARY = "eyJhbGciOiJFZDI1NTE5IiwidHlwIjoiSldUIn0.eyJhIjoiMSJ9.PWMx1IQkiK5QOAd1CgFTmhDm4WN4jrzHOtUdRZIbWXzsjx1SErR0kd_110i3CQeQBbd69lYCNSbWsMkF2hCVDg"
  SIGNED_MAP    = {"signature"=>"PWMx1IQkiK5QOAd1CgFTmhDm4WN4jrzHOtUdRZIbWXzsjx1SErR0kd_110i3CQeQBbd69lYCNSbWsMkF2hCVDg", "payload"=>"eyJhIjoiMSJ9", "protected"=>"eyJhbGciOiJFZDI1NTE5IiwidHlwIjoiSldUIn0"}
  JWT_PAYLOAD   = {"a"=>"1"}
  JWT_PROTECTED = {"alg"=>"Ed25519", "typ"=>"JWT"}
  JWT_SIGNATURE = [61,99,49,212,132,36,136,174,80,56,7,117,10,1,83,154,16,230,225,99,120,142,188,199,58,213,29,69,146,27,89,124,236,143,29,82,18,180,116,145,223,245,215,72,183,9,7,144,5,183,122,246,86,2,53,38,214,176,201,5,218,16,149,14].pack('C*')

  def test_peek_payload
    assert_equal JWT_PAYLOAD, JOSE::JWT.peek_payload(SIGNED_BINARY)
    assert_equal JWT_PAYLOAD, JOSE::JWT.peek_payload(SIGNED_MAP)
  end

  def test_peek_protected
    assert_equal JWT_PROTECTED, JOSE::JWT.peek_protected(SIGNED_BINARY)
    assert_equal JWT_PROTECTED, JOSE::JWT.peek_protected(SIGNED_MAP)
  end

  def test_peek_signature
    assert_equal JWT_SIGNATURE, JOSE::JWT.peek_signature(SIGNED_BINARY)
    assert_equal JWT_SIGNATURE, JOSE::JWT.peek_signature(SIGNED_MAP)
  end

end
