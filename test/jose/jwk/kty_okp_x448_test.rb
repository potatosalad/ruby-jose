require 'test_helper'

class JOSE::JWK::KTY_OKP_X448Test < Minitest::Test

  SECRET_JWK_JSON = "{\"crv\":\"X448\",\"d\":\"eA8RT6j3m-M0NsF6F1-4Cl9ZZVFFMZ-voewkFejZx20fswt3NK2kDzhDUYMDiv6gJh3S_s39HNo\",\"kty\":\"OKP\",\"x\":\"VneDBlIdMcDlRLY5FIihN1muiel5U2BDc4QoGj-0mmUWqVhhOFzeheGefoApJ3QwuMSD45PZL1U\"}"
  PUBLIC_JWK_JSON = "{\"crv\":\"X448\",\"kty\":\"OKP\",\"x\":\"VneDBlIdMcDlRLY5FIihN1muiel5U2BDc4QoGj-0mmUWqVhhOFzeheGefoApJ3QwuMSD45PZL1U\"}"
  SECRET_EPK_JSON = "{\"crv\":\"X448\",\"d\":\"-GxK8dpD2supp0MbaJ8sK647XWgY62rn3TgFaIT_aZbqcHheKxLmfgvTFG3xhhFskxN70qjmbp8\",\"kty\":\"OKP\",\"x\":\"zFMLgdZr7OAX3b_zz6zWwn9X-D65fEv-Zxa0YoU9dpxnarbPsFXUPOXeKPT4v9IM_ezKLXO0wLs\"}"
  PUBLIC_EPK_JSON = "{\"crv\":\"X448\",\"kty\":\"OKP\",\"x\":\"zFMLgdZr7OAX3b_zz6zWwn9X-D65fEv-Zxa0YoU9dpxnarbPsFXUPOXeKPT4v9IM_ezKLXO0wLs\"}"
  SHARED_SECRET   = [174,19,138,110,33,162,91,217,47,202,190,252,140,125,94,30,190,157,94,11,166,202,245,101,214,107,7,220,124,26,5,126,244,53,50,123,172,214,191,172,180,225,2,198,79,160,176,36,53,6,234,180,20,119,15,162].pack('C*')

  def test_generate_key
    jwk_secret = JOSE::JWK.generate_key([:okp, :X448])
    refute_equal JOSE::JWK.thumbprint(jwk_secret), JOSE::JWK.thumbprint(JOSE::JWK.generate_key(jwk_secret))
  end

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
    plain_jwk = JOSE::JWK.from_binary(SECRET_JWK_JSON)
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

  def test_to_openssh_key_and_from_openssh_key
    secret_jwk = JOSE::JWK.from_binary(SECRET_JWK_JSON)
    assert_equal secret_jwk, JOSE::JWK.from_openssh_key(JOSE::JWK.to_openssh_key(secret_jwk))
  end

  def test_property_of_to_openssh_key_and_from_openssh_key
    skip("Very slow, needs to be implemented in C.")
    # property_of {
    #   gen_jwk_kty_okp(:X448)
    # }.check { |tuple|
    #   jwk_secret = tuple[0]
    #   assert_equal jwk_secret, JOSE::JWK.from_openssh_key(JOSE::JWK.to_openssh_key(jwk_secret))
    # }
  end

end
