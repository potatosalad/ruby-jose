require 'test_helper'

class JOSE::JWS::ALG_RSA_PSSTest < Minitest::Test

  def test_generate_key
    RSAGenerator.cache do
      [
        'PS256',
        'PS384',
        'PS512'
      ].each do |alg|
        jwk = JOSE::JWS.generate_key({'alg' => alg})
        plain_text = SecureRandom.random_bytes(8)
        signed_text = JOSE::JWK.sign(plain_text, jwk).compact
        verified, payload, = JOSE::JWK.verify(signed_text, jwk)
        assert verified
        assert_equal payload, plain_text
      end
    end
  end

end
