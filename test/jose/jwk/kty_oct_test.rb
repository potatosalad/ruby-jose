require 'test_helper'

class JOSE::JWK::KTY_octTest < Minitest::Test

  SECRET_OCT_DATA = [224,172,57,69,122,37,35,200,133,247,237,254,18,26,84,234,0,237,83,95,242,10,237,57,84,106,142,244,237,135,43,163,73,213,67,210,60,5,169,29,177,152,148,41,126,110,15,83,67,61,116,63,69,214,116,236,35,244,204,93,131,15,104,147].pack('C*')
  SECRET_JWK_JSON = "{\"k\":\"4Kw5RXolI8iF9-3-EhpU6gDtU1_yCu05VGqO9O2HK6NJ1UPSPAWpHbGYlCl-bg9TQz10P0XWdOwj9Mxdgw9okw\",\"kty\":\"oct\"}"
  THUMBPRINT      = "AtWsCq3xje2QQh_o8GJ_Sftt8ttZm66n87fjRoCaYf4"

  def test_from_binary_and_to_binary
    secret_jwk = JOSE::JWK.from_binary(SECRET_JWK_JSON)
    assert_equal SECRET_JWK_JSON, JOSE::JWK.to_binary(secret_jwk)
  end

  def test_from_map_and_to_map
    secret_jwk = JOSE::JWK.from_binary(SECRET_JWK_JSON)
    secret_map = secret_jwk.to_map
    assert_equal secret_jwk, JOSE::JWK.from_map(secret_map)
    assert_raises(ArgumentError) { JOSE::JWK.from_map(secret_map.delete('k')) }
  end

  def test_to_key
    secret_jwk = JOSE::JWK.from_binary(SECRET_JWK_JSON)
    assert_equal SECRET_OCT_DATA, JOSE::JWK.to_key(secret_jwk)
    assert_equal SECRET_OCT_DATA, JOSE::JWK.to_oct(secret_jwk)
  end

  def test_to_oct
    secret_jwk = JOSE::JWK.from_binary(SECRET_JWK_JSON)
    assert_equal SECRET_OCT_DATA, JOSE::JWK.to_oct(secret_jwk)
  end

  def test_thumbprint
    secret_jwk = JOSE::JWK.from_binary(SECRET_JWK_JSON)
    assert_equal THUMBPRINT, JOSE::JWK.thumbprint(secret_jwk)
  end

  def test_block_encryptor
    alg = 'PBES2-HS256+A128KW'
    enc = 'A128GCM'
    p2c = SecureRandom.random_number(1000..4000)
    p2s = JOSE.urlsafe_encode64(SecureRandom.random_bytes(8))
    assert_equal JOSE::Map['alg' => alg, 'enc' => enc, 'p2c' => p2c, 'p2s' => p2s], JOSE::JWK.block_encryptor(JOSE::JWK.generate_key([:oct, 16]).merge(JOSE::Map['alg' => alg, 'enc' => enc, 'p2c' => p2c, 'p2s' => p2s, 'use' => 'enc']))
    assert_equal JOSE::Map['alg' => 'dir', 'enc' => 'A128GCM'], JOSE::JWK.block_encryptor(JOSE::JWK.generate_key([:oct, 16]))
    assert_equal JOSE::Map['alg' => 'dir', 'enc' => 'A192GCM'], JOSE::JWK.block_encryptor(JOSE::JWK.generate_key([:oct, 24]))
    assert_equal JOSE::Map['alg' => 'dir', 'enc' => 'A256GCM'], JOSE::JWK.block_encryptor(JOSE::JWK.generate_key([:oct, 32]))
    assert_equal JOSE::Map['alg' => 'dir', 'enc' => 'A192CBC-HS384'], JOSE::JWK.block_encryptor(JOSE::JWK.generate_key([:oct, 48]))
    assert_equal JOSE::Map['alg' => 'dir', 'enc' => 'A256CBC-HS512'], JOSE::JWK.block_encryptor(JOSE::JWK.generate_key([:oct, 64]))
    assert_raises(ArgumentError) { JOSE::JWK.block_encryptor(JOSE::JWK.generate_key([:oct, 0])) }
  end

  def test_derive_key
    secret_jwk = JOSE::JWK.from_binary(SECRET_JWK_JSON)
    assert_equal SECRET_OCT_DATA, JOSE::JWK.derive_key(secret_jwk)
  end

  def test_generate_key
    secret_jwk = JOSE::JWK.from_binary(SECRET_JWK_JSON)
    second_jwk = JOSE::JWK.generate_key(secret_jwk)
    assert_equal SECRET_OCT_DATA.bytesize, JOSE::JWK.to_oct(second_jwk).bytesize
    refute_equal THUMBPRINT, JOSE::JWK.thumbprint(second_jwk)
    assert_raises(ArgumentError) { JOSE::JWK.generate_key([:oct, 1.0]) }
  end

  def test_signer
    oct256_jwk = JOSE::JWK.generate_key([:oct, 32])
    oct384_jwk = JOSE::JWK.generate_key([:oct, 48])
    oct512_jwk = JOSE::JWK.generate_key([:oct, 64])
    assert_equal JOSE::Map['alg' => 'HS256'], JOSE::JWK.signer(oct256_jwk)
    assert_equal JOSE::Map['alg' => 'HS384'], JOSE::JWK.signer(oct384_jwk)
    assert_equal JOSE::Map['alg' => 'HS512'], JOSE::JWK.signer(oct512_jwk)
    extra_oct256_jwk = oct256_jwk.merge({'alg' => 'HS512', 'use' => 'sig'})
    assert_equal JOSE::Map['alg' => 'HS512'], JOSE::JWK.signer(extra_oct256_jwk)
  end

  def test_verifier
    oct256_jwk = JOSE::JWK.generate_key([:oct, 32])
    oct384_jwk = JOSE::JWK.generate_key([:oct, 48])
    oct512_jwk = JOSE::JWK.generate_key([:oct, 64])
    assert_equal ['HS256'], JOSE::JWK.verifier(oct256_jwk)
    assert_equal ['HS256', 'HS384'], JOSE::JWK.verifier(oct384_jwk)
    assert_equal ['HS256', 'HS384', 'HS512'], JOSE::JWK.verifier(oct512_jwk)
    extra_oct256_jwk = oct256_jwk.merge({'alg' => 'HS512', 'use' => 'sig'})
    assert_equal ['HS512'], JOSE::JWK.verifier(extra_oct256_jwk)
  end

  def test_key_encryptor
    secret_jwk = JOSE::JWK.from_binary(SECRET_JWK_JSON)
    key_encryptor = secret_jwk.kty.key_encryptor(secret_jwk.fields, 'test')
    assert_equal 'PBES2-HS256+A128KW', key_encryptor['alg']
  end

end
