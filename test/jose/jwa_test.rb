require 'test_helper'

class JOSE::JWATest < Minitest::Test

  def test_supports
    crypto_fallback = JOSE.crypto_fallback
    unsecured_signing = JOSE.unsecured_signing
    begin
      JOSE.crypto_fallback = true
      JOSE.unsecured_signing = true
      supported = {
        :jwe => {
          :alg => [
            'A128GCMKW',
            'A192GCMKW',
            'A256GCMKW',
            'A128KW',
            'A192KW',
            'A256KW',
            'ECDH-ES',
            'ECDH-ES+A128KW',
            'ECDH-ES+A192KW',
            'ECDH-ES+A256KW',
            'PBES2-HS256+A128KW',
            'PBES2-HS384+A192KW',
            'PBES2-HS512+A256KW',
            'RSA1_5',
            'RSA-OAEP',
            'RSA-OAEP-256',
            'dir'
          ],
          :enc => [
            'A128GCM',
            'A192GCM',
            'A256GCM',
            'A128CBC-HS256',
            'A192CBC-HS384',
            'A256CBC-HS512'
          ],
          :zip => [
            'DEF'
          ]
        },
        :jwk => {
          :kty => [
            'EC',
            'OKP',
            'RSA',
            'oct'
          ],
          :kty_EC_crv => [
            'P-256',
            'P-384',
            'P-521'
          ],
          :kty_OKP_crv =>[
            'Ed25519',
            'Ed25519ph',
            'Ed448',
            'Ed448ph',
            'X25519',
            'X448'
          ]
        },
        :jws => {
          :alg => [
            'Ed25519',
            'Ed25519ph',
            'Ed448',
            'Ed448ph',
            'ES256',
            'ES384',
            'ES512',
            'HS256',
            'HS384',
            'HS512',
            'PS256',
            'PS384',
            'PS512',
            'RS256',
            'RS384',
            'RS512',
            'none'
          ]
        }
      }
      assert_equal supported, JOSE::JWA.supports
    ensure
      JOSE.crypto_fallback = crypto_fallback
      JOSE.unsecured_signing = unsecured_signing
    end
  end

end
