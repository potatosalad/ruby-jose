require 'test_helper'

class JOSE::JWK::KTY_RSATest < Minitest::Test

  SECRET_JWK_JSON = "{\"d\":\"ghUlwEYdrZF-TxysKsRppvPxHG1X4qjh9VmNLglKIcqUQb1ngSdq7VZ0zHCBddDjECN87fzrBm7wz74zniKAsaT4VU4JWLOwvEq0fAW6f-L7gn91eZhklxUrUgbUhpLjYGtx2lCDSMA0_P9TqeCzHwMWcvx86fGW0CkGSjz-16E\",\"dp\":\"M0yue0VjsxkG08bRFNO--mugs0Zvf0skNNT0393UzPp3GDseU7bVhjwFNw6T3GS2YXHWGSEn1sGrEtUulmGrMQ\",\"dq\":\"QWxAUGzS8SaZe_KNrS5BjmLRbDXNgSmZIDMZgDtyNa0sT97zZsJ0WNrp73_rHn_0dxqTYnkJld-Jlxq-u8uFmQ\",\"e\":\"AQAB\",\"kty\":\"RSA\",\"n\":\"6zyrhQgzZOaeauWOFbfhnv8o7F9y1iqZZk1ILqq72UuXHl1vVjwOpD5f4GQ8JMbWtH-qOjRvUj5suy8wWq-rRVp8lHkpZClosTbMoYFI9UxfVYMA45-xnZfrFy3w9obmDWhfLGN_KSeeM4X_rErmXjMi-T2sBX_0yySbPiFqLOU\",\"p\":\"-hNhau_os7GVdN9qoM5VuuOmGeFu7umY3kehVs6A7e8rFg38x1pvTS_5qRatahzYIQ-bDtaoyUOYf1uBLBslTQ\",\"q\":\"8M9MSPEF_skg3I8ON0v4MAcg9GoiWTeEfX6JTNXOlap6xjRL8Lp_lI6cudkEC9WKk2sFuR9jUmM6qDLPOSf5-Q\",\"qi\":\"0kUJWgjRen39Ys5d3ZK8HzlFIA34dbkEQHnEiw0qVakHGpRGsBMofwrmheAPSH3kTSn0ETeiwPm7JZ8zEaNIaw\"}"
  PUBLIC_JWK_JSON = "{\"e\":\"AQAB\",\"kty\":\"RSA\",\"n\":\"6zyrhQgzZOaeauWOFbfhnv8o7F9y1iqZZk1ILqq72UuXHl1vVjwOpD5f4GQ8JMbWtH-qOjRvUj5suy8wWq-rRVp8lHkpZClosTbMoYFI9UxfVYMA45-xnZfrFy3w9obmDWhfLGN_KSeeM4X_rErmXjMi-T2sBX_0yySbPiFqLOU\"}"

  def test_from_binary_and_to_binary
    secret_jwk = JOSE::JWK.from_binary(SECRET_JWK_JSON)
    public_jwk = JOSE::JWK.from_binary(PUBLIC_JWK_JSON)
    assert_equal SECRET_JWK_JSON, JOSE::JWK.to_binary(secret_jwk)
    assert_equal PUBLIC_JWK_JSON, JOSE::JWK.to_binary(public_jwk)
    assert_equal public_jwk,      JOSE::JWK.to_public(secret_jwk)
  end

  def test_from_key_and_to_key
    secret_jwk = JOSE::JWK.from_binary(SECRET_JWK_JSON)
    public_jwk = JOSE::JWK.from_binary(PUBLIC_JWK_JSON)
    secret_key = JOSE::JWK.to_key(secret_jwk)
    public_key = JOSE::JWK.to_key(public_jwk)
    assert_equal secret_jwk, JOSE::JWK.from_key(secret_key)
    assert_equal public_jwk, JOSE::JWK.from_key(public_key)
  end

  def test_generate_key
    jwk1 = JOSE::JWK.generate_key([:rsa, 128])
    jwk2 = JOSE::JWK.generate_key([:rsa, 128, 13])
    jwk3 = JOSE::JWK.generate_key(jwk2)
    refute_equal JOSE::JWK.thumbprint(jwk1), JOSE::JWK.thumbprint(jwk2)
    refute_equal JOSE::JWK.thumbprint(jwk1), JOSE::JWK.thumbprint(jwk3)
    refute_equal JOSE::JWK.thumbprint(jwk2), JOSE::JWK.thumbprint(jwk3)
  end

  def test_block_encryptor
    RSAGenerator.cache do
      plain_jwk = JOSE::JWK.from(SECRET_JWK_JSON)
      assert_equal JOSE::Map['alg' => 'RSA-OAEP', 'enc' => 'A128GCM'], JOSE::JWK.block_encryptor(plain_jwk)
      extra_jwk = plain_jwk.merge({'alg' => 'RSA-OAEP-256', 'enc' => 'A256GCM', 'use' => 'enc'})
      assert_equal JOSE::Map['alg' => 'RSA-OAEP-256', 'enc' => 'A256GCM'], JOSE::JWK.block_encryptor(extra_jwk)
    end
  end

  def test_signer
    RSAGenerator.cache do
      plain_jwk = JOSE::JWK.from(SECRET_JWK_JSON)
      assert_equal JOSE::Map['alg' => 'RS256'], JOSE::JWK.signer(plain_jwk)
      extra_jwk = plain_jwk.merge({'alg' => 'PS256', 'use' => 'sig'})
      assert_equal JOSE::Map['alg' => 'PS256'], JOSE::JWK.signer(extra_jwk)
      public_jwk = JOSE::JWK.from(PUBLIC_JWK_JSON)
      assert_raises(ArgumentError) { JOSE::JWK.signer(public_jwk) }
    end
  end

  def test_verifier
    RSAGenerator.cache do
      plain_jwk = JOSE::JWK.from(SECRET_JWK_JSON)
      assert_equal ['PS256', 'PS384', 'PS512', 'RS256', 'RS384', 'RS512'], JOSE::JWK.verifier(plain_jwk)
      extra_jwk = plain_jwk.merge({'alg' => 'PS256', 'use' => 'sig'})
      assert_equal ['PS256'], JOSE::JWK.verifier(extra_jwk)
    end
  end

  def test_key_encryptor
    RSAGenerator.cache do
      secret_jwk = JOSE::JWK.from_binary(SECRET_JWK_JSON)
      key_encryptor = secret_jwk.kty.key_encryptor(secret_jwk.fields, 'test')
      assert_equal 'PBES2-HS256+A128KW', key_encryptor['alg']
    end
  end

  def test_sfm_and_crt
    RSAGenerator.cache do
      jwk_crt = JOSE::JWK.from_binary(SECRET_JWK_JSON)
      jwk_sfm = jwk_crt.to_map.except('dp', 'dq', 'p', 'q', 'qi')
      assert_equal jwk_crt, JOSE::JWK.from(jwk_sfm)
    end
  end

end
