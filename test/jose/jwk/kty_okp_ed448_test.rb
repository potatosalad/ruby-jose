require 'test_helper'

class JOSE::JWK::KTY_OKP_Ed448Test < Minitest::Test

  SECRET_JWK_JSON = "{\"crv\":\"Ed448\",\"d\":\"dWq9WoZifBc0XZ_yRJBv1TbFCj82CZHJg8eK0HGLl2DvVMIn3hgds973-05ChhehlGOoN_MdPOlx\",\"kty\":\"OKP\",\"x\":\"DEZEbekalV9f3_n5mfeJllxsZLs9y49uGSXjGHsr2LKttmEY7DtMhRzpQDSuvd4F4OuAonS-VywA\"}"
  PUBLIC_JWK_JSON = "{\"crv\":\"Ed448\",\"kty\":\"OKP\",\"x\":\"DEZEbekalV9f3_n5mfeJllxsZLs9y49uGSXjGHsr2LKttmEY7DtMhRzpQDSuvd4F4OuAonS-VywA\"}"

  def test_generate_key
    jwk_secret = JOSE::JWK.generate_key([:okp, :Ed448])
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
    # property_of {
    #   Tuple.new([
    #     gen_jwk_use_sig('Ed448'),
    #     SecureRandom.random_bytes(range(0, size))
    #   ])
    # }.check { |tuple|
    #   jwk_secret = tuple[0][0]
    #   jwk_public = tuple[0][1]
    #   plain_text = tuple[1]
    #   signed_binary = JOSE::JWK.sign(plain_text, jwk_secret).compact
    #   verified, payload, = JOSE::JWK.verify(signed_binary, jwk_public)
    #   assert verified
    #   assert_equal plain_text, payload
    # }
  end

  def test_to_openssh_key_and_from_openssh_key
    secret_jwk = JOSE::JWK.from_binary(SECRET_JWK_JSON)
    assert_equal secret_jwk, JOSE::JWK.from_openssh_key(JOSE::JWK.to_openssh_key(secret_jwk))
  end

  def test_property_of_to_openssh_key_and_from_openssh_key
    skip("Very slow, needs to be implemented in C.")
    # property_of {
    #   gen_jwk_kty_okp(:Ed448)
    # }.check { |tuple|
    #   jwk_secret = tuple[0]
    #   assert_equal jwk_secret, JOSE::JWK.from_openssh_key(JOSE::JWK.to_openssh_key(jwk_secret))
    # }
  end

  def test_signer
    plain_jwk = JOSE::JWK.from(SECRET_JWK_JSON)
    assert_equal JOSE::Map['alg' => 'Ed448'], JOSE::JWK.signer(plain_jwk)
    extra_jwk = plain_jwk.merge({'alg' => 'Ed448', 'use' => 'sig'})
    assert_equal JOSE::Map['alg' => 'Ed448'], JOSE::JWK.signer(extra_jwk)
    public_jwk = JOSE::JWK.from(PUBLIC_JWK_JSON)
    assert_raises(ArgumentError) { JOSE::JWK.signer(public_jwk) }
  end

  def test_verifier
    plain_jwk = JOSE::JWK.from(SECRET_JWK_JSON)
    assert_equal ['Ed448'], JOSE::JWK.verifier(plain_jwk)
    extra_jwk = plain_jwk.merge({'alg' => 'Ed448', 'use' => 'sig'})
    assert_equal ['Ed448'], JOSE::JWK.verifier(extra_jwk)
  end

  def test_key_encryptor
    secret_jwk = JOSE::JWK.from_binary(SECRET_JWK_JSON)
    key_encryptor = secret_jwk.kty.key_encryptor(secret_jwk.fields, 'test')
    assert_equal 'PBES2-HS256+A128KW', key_encryptor['alg']
  end

end
