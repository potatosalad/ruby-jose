require 'test_helper'

class JOSE::JWKTest < Minitest::Test

  def test_property_of_from
    property_of {
      gen_jwk()
    }.check { |tuple|
      secret_jwk = tuple[0]
      public_jwk = tuple[1]
      assert_equal secret_jwk, JOSE::JWK.from(JOSE::JWK.to_binary(secret_jwk))
      assert_equal secret_jwk, JOSE::JWK.from(JOSE::JWK.to_map(secret_jwk))
      assert_equal public_jwk, JOSE::JWK.from(JOSE::JWK.to_binary(public_jwk))
      assert_equal public_jwk, JOSE::JWK.from(JOSE::JWK.to_map(public_jwk))
      assert_equal [secret_jwk, public_jwk, secret_jwk, public_jwk], JOSE::JWK.from([JOSE::JWK.to_binary(secret_jwk), JOSE::JWK.to_map(public_jwk), secret_jwk, public_jwk])
      password = SecureRandom.urlsafe_base64(8)
      encrypted_jwk_binary = JOSE::JWK.to_binary(secret_jwk, password)
      decrypted_jwk, = JOSE::JWK.from(encrypted_jwk_binary, password)
      assert_equal secret_jwk, decrypted_jwk
      encrypted_jwk_map = JOSE::JWK.to_map(secret_jwk, password)
      decrypted_jwk, = JOSE::JWK.from(encrypted_jwk_map, password)
      assert_equal secret_jwk, decrypted_jwk
    }
  end

  def test_from
    assert_raises(ArgumentError) { JOSE::JWK.from(1) }
  end

  def test_from_binary
    jwk1 = JOSE::JWK.generate_key([:oct, 1])
    jwk2 = JOSE::JWK.generate_key([:oct, 2])
    binary_array = [
      jwk1.to_binary,
      jwk2.to_binary
    ]
    jwks = JOSE::JWK.from_binary(binary_array)
    assert_equal jwk1, jwks[0]
    assert_equal jwk2, jwks[1]
    assert_raises(ArgumentError) { JOSE::JWK.from_binary(1) }
  end

  def test_from_file_and_to_file
    tempfile = Tempfile.new('jwk')
    begin
      jwk_oct = JOSE::JWK.generate_key([:oct, 1])
      JOSE::JWK.to_file(jwk_oct, tempfile.path)
      assert_equal jwk_oct, JOSE::JWK.from_file(tempfile.path)
      JOSE::JWK.to_oct_file(jwk_oct, tempfile.path)
      assert_equal jwk_oct, JOSE::JWK.from_oct_file(tempfile.path)
      jwk_ed25519 = JOSE::JWK.generate_key([:okp, :Ed25519])
      JOSE::JWK.to_openssh_key_file(jwk_ed25519, tempfile.path)
      assert_equal jwk_ed25519, JOSE::JWK.from_openssh_key_file(tempfile.path)
      jwk_ec256_secret = JOSE::JWK.generate_key([:ec, "P-256"])
      jwk_ec256_public = JOSE::JWK.to_public(jwk_ec256_secret)
      JOSE::JWK.to_pem_file(jwk_ec256_secret, tempfile.path)
      assert_equal jwk_ec256_secret, JOSE::JWK.from_pem_file(tempfile.path)
      JOSE::JWK.to_public_file(jwk_ec256_secret, tempfile.path)
      assert_equal jwk_ec256_public, JOSE::JWK.from_file(tempfile.path)
      JOSE::JWK.to_pem_file(jwk_ec256_public, tempfile.path)
      assert_equal jwk_ec256_public, JOSE::JWK.from_pem_file(tempfile.path)
    ensure
      tempfile.unlink
    end
  end

  def test_from_okp_and_to_okp
    okp_vectors = [
      [:Ed25519,   [77,55,145,129,165,187,226,143,188,140,61,104,87,201,145,133,253,129,57,243,242,195,150,212,103,60,163,59,220,156,149,108,14,178,245,236,59,188,194,41,139,148,2,125,27,252,174,134,93,12,229,221,211,42,233,48,162,231,70,228,62,46,240,149].pack('C*')],
      [:Ed25519,   [14,178,245,236,59,188,194,41,139,148,2,125,27,252,174,134,93,12,229,221,211,42,233,48,162,231,70,228,62,46,240,149].pack('C*')],
      [:Ed25519ph, [66,87,195,90,240,202,40,161,243,233,135,160,14,207,13,144,60,189,176,244,48,108,219,23,66,83,116,235,251,129,234,250,50,235,167,100,221,193,52,118,237,47,245,101,161,0,201,229,247,250,183,238,191,13,210,243,127,10,73,3,228,114,5,75].pack('C*')],
      [:Ed25519ph, [50,235,167,100,221,193,52,118,237,47,245,101,161,0,201,229,247,250,183,238,191,13,210,243,127,10,73,3,228,114,5,75].pack('C*')],
      [:Ed448,     [126,157,160,184,161,41,66,7,194,42,86,166,248,20,210,36,52,215,156,220,176,16,121,27,164,217,87,147,111,159,157,233,245,129,19,192,73,188,126,101,46,13,59,207,145,89,144,105,11,216,45,152,173,89,194,177,244,96,47,191,18,118,201,94,244,125,216,216,131,83,5,195,23,100,63,43,100,179,212,239,200,231,139,65,227,138,96,230,21,229,93,204,253,116,161,145,55,184,186,175,2,20,184,19,94,197,40,53,85,244,128,195,11,128].pack('C*')],
      [:Ed448,     [96,47,191,18,118,201,94,244,125,216,216,131,83,5,195,23,100,63,43,100,179,212,239,200,231,139,65,227,138,96,230,21,229,93,204,253,116,161,145,55,184,186,175,2,20,184,19,94,197,40,53,85,244,128,195,11,128].pack('C*')],
      [:Ed448ph,   [47,115,118,232,157,225,157,238,6,59,179,43,222,238,46,205,232,149,147,185,62,48,65,183,162,148,151,232,100,21,14,172,187,179,84,42,155,173,147,74,147,40,85,156,191,99,10,101,26,20,169,202,73,90,242,224,90,117,40,65,240,171,206,111,179,237,230,25,214,13,79,112,91,254,3,18,33,242,21,124,118,88,29,55,108,82,208,120,1,23,225,126,211,23,78,67,99,141,125,107,46,76,32,92,106,190,24,136,210,239,38,190,39,128].pack('C*')],
      [:Ed448ph,   [117,40,65,240,171,206,111,179,237,230,25,214,13,79,112,91,254,3,18,33,242,21,124,118,88,29,55,108,82,208,120,1,23,225,126,211,23,78,67,99,141,125,107,46,76,32,92,106,190,24,136,210,239,38,190,39,128].pack('C*')],
      [:X25519,    [96,217,201,235,198,232,54,173,154,12,17,116,68,172,135,50,63,55,187,138,174,19,134,205,121,137,69,151,134,129,133,113,28,243,136,7,83,100,35,65,114,23,222,151,25,105,72,233,121,149,26,16,131,149,59,96,153,132,101,23,61,57,89,26].pack('C*')],
      [:X25519,    [28,243,136,7,83,100,35,65,114,23,222,151,25,105,72,233,121,149,26,16,131,149,59,96,153,132,101,23,61,57,89,26].pack('C*')],
      [:X448,      [100,115,156,9,104,108,224,186,141,185,206,67,92,151,50,45,2,245,87,45,212,135,87,145,46,223,1,116,107,241,220,141,177,140,119,228,43,145,168,135,198,232,51,204,211,54,246,74,36,152,213,235,93,185,167,234,251,10,12,119,252,249,184,211,222,195,81,107,102,81,174,50,241,30,16,14,22,210,15,190,220,14,53,42,181,96,115,39,108,157,58,218,129,206,147,141,103,64,162,240,177,150,44,63,82,69,190,181,200,157,191,82].pack('C*')],
      [:X448,      [251,10,12,119,252,249,184,211,222,195,81,107,102,81,174,50,241,30,16,14,22,210,15,190,220,14,53,42,181,96,115,39,108,157,58,218,129,206,147,141,103,64,162,240,177,150,44,63,82,69,190,181,200,157,191,82].pack('C*')]
    ]
    jwk_vectors = [
      "{\"crv\":\"Ed25519\",\"d\":\"TTeRgaW74o-8jD1oV8mRhf2BOfPyw5bUZzyjO9yclWw\",\"kty\":\"OKP\",\"x\":\"DrL17Du8wimLlAJ9G_yuhl0M5d3TKukwoudG5D4u8JU\"}",
      "{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"DrL17Du8wimLlAJ9G_yuhl0M5d3TKukwoudG5D4u8JU\"}",
      "{\"crv\":\"Ed25519ph\",\"d\":\"QlfDWvDKKKHz6YegDs8NkDy9sPQwbNsXQlN06_uB6vo\",\"kty\":\"OKP\",\"x\":\"MuunZN3BNHbtL_VloQDJ5ff6t-6_DdLzfwpJA-RyBUs\"}",
      "{\"crv\":\"Ed25519ph\",\"kty\":\"OKP\",\"x\":\"MuunZN3BNHbtL_VloQDJ5ff6t-6_DdLzfwpJA-RyBUs\"}",
      "{\"crv\":\"Ed448\",\"d\":\"fp2guKEpQgfCKlam-BTSJDTXnNywEHkbpNlXk2-fnen1gRPASbx-ZS4NO8-RWZBpC9gtmK1ZwrH0\",\"kty\":\"OKP\",\"x\":\"YC-_EnbJXvR92NiDUwXDF2Q_K2Sz1O_I54tB44pg5hXlXcz9dKGRN7i6rwIUuBNexSg1VfSAwwuA\"}",
      "{\"crv\":\"Ed448\",\"kty\":\"OKP\",\"x\":\"YC-_EnbJXvR92NiDUwXDF2Q_K2Sz1O_I54tB44pg5hXlXcz9dKGRN7i6rwIUuBNexSg1VfSAwwuA\"}",
      "{\"crv\":\"Ed448ph\",\"d\":\"L3N26J3hne4GO7Mr3u4uzeiVk7k-MEG3opSX6GQVDqy7s1Qqm62TSpMoVZy_YwplGhSpykla8uBa\",\"kty\":\"OKP\",\"x\":\"dShB8KvOb7Pt5hnWDU9wW_4DEiHyFXx2WB03bFLQeAEX4X7TF05DY419ay5MIFxqvhiI0u8mvieA\"}",
      "{\"crv\":\"Ed448ph\",\"kty\":\"OKP\",\"x\":\"dShB8KvOb7Pt5hnWDU9wW_4DEiHyFXx2WB03bFLQeAEX4X7TF05DY419ay5MIFxqvhiI0u8mvieA\"}",
      "{\"crv\":\"X25519\",\"d\":\"YNnJ68boNq2aDBF0RKyHMj83u4quE4bNeYlFl4aBhXE\",\"kty\":\"OKP\",\"x\":\"HPOIB1NkI0FyF96XGWlI6XmVGhCDlTtgmYRlFz05WRo\"}",
      "{\"crv\":\"X25519\",\"kty\":\"OKP\",\"x\":\"HPOIB1NkI0FyF96XGWlI6XmVGhCDlTtgmYRlFz05WRo\"}",
      "{\"crv\":\"X448\",\"d\":\"ZHOcCWhs4LqNuc5DXJcyLQL1Vy3Uh1eRLt8BdGvx3I2xjHfkK5Goh8boM8zTNvZKJJjV6125p-o\",\"kty\":\"OKP\",\"x\":\"-woMd_z5uNPew1FrZlGuMvEeEA4W0g--3A41KrVgcydsnTragc6TjWdAovCxliw_UkW-tcidv1I\"}",
      "{\"crv\":\"X448\",\"kty\":\"OKP\",\"x\":\"-woMd_z5uNPew1FrZlGuMvEeEA4W0g--3A41KrVgcydsnTragc6TjWdAovCxliw_UkW-tcidv1I\"}"
    ]
    okp_vectors.each_with_index do |okp, index|
      jwk = JOSE::JWK.from(jwk_vectors[index])
      assert_equal jwk, JOSE::JWK.from_okp(okp), "from_okp failed on test vector ##{index + 1}"
      assert_equal okp, JOSE::JWK.to_okp(jwk), "to_okp failed on test vector ##{index + 1}"
    end
  end

end
