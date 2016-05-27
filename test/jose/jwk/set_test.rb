require 'test_helper'

class JOSE::JWK::SetTest < Minitest::Test

  def test_from_map_and_to_map
    jwk1_json = "{\"crv\":\"P-256\",\"d\":\"cDwKGuX0AY4Ewy6mnJ7sHEewiTZQyg4Zh7l93uaAMHg\",\"kty\":\"EC\",\"x\":\"V3Sm3I_84c2NjGxnkt_oKiq_0bfG-2NqVaReklg1OyE\",\"y\":\"tE9IjVswZEsM112r809c3W3mqMvndnTGh4u_ECQo13A\"}"
    jwks_json = "{\"keys\":[{\"crv\":\"P-256\",\"d\":\"cDwKGuX0AY4Ewy6mnJ7sHEewiTZQyg4Zh7l93uaAMHg\",\"kty\":\"EC\",\"x\":\"V3Sm3I_84c2NjGxnkt_oKiq_0bfG-2NqVaReklg1OyE\",\"y\":\"tE9IjVswZEsM112r809c3W3mqMvndnTGh4u_ECQo13A\"},{\"crv\":\"P-256\",\"d\":\"KVuVWSmolsqRXgFs9SZ6OWtjoXrLeOEwqKU2FB7VjPs\",\"kty\":\"EC\",\"x\":\"--73xWmupERRDd0BO_yoxEw126hCGR_tAqvmXGXHUHA\",\"y\":\"Etiodwd2oLF8d3K1NeUVRh3qAZS0yH1EyvNjn7EbAEg\"},{\"crv\":\"P-256\",\"d\":\"5ti6oYBLyJIoOSkQ2msEog1EHf45xFqA63FW2lCu5bc\",\"kty\":\"EC\",\"x\":\"ZIvtLzVFjikHrhkbKMSr166YO-bpcGQ6IaunX84n_uo\",\"y\":\"p7MnduhYZZJS0i6Ct5rfk8RzSyvITrRz3K946uUvTyg\"}]}"
    jwk1 = JOSE::JWK.from(jwk1_json)
    jwks = JOSE::JWK.from(jwks_json)
    assert_equal jwk1, jwks.keys[0]
    assert_equal jwks_json, jwks.to_binary
  end

end
