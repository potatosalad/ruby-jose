require 'test_helper'

class CAVPTest < Minitest::Test

  def test_curve25519_rfc7748_curve25519
    vectors = [
      [
        31029842492115040904895560451863089656472772604678260265531221036453811406496,  # Input scalar
        34426434033919594451155107781188821651316167215306631574996226621102155684838,  # Input u-coordinate
        hexstr2lint("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552") # Output u-coordinate
      ],
      [
        35156891815674817266734212754503633747128614016119564763269015315466259359304,  # Input scalar
        8883857351183929894090759386610649319417338800022198945255395922347792736741,   # Input u-coordinate
        hexstr2lint("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957") # Output u-coordinate
      ]
    ]
    vectors.each do |(input_scalar, input_u_coordinate, output_u_coordinate)|
      input_scalar        = JOSE::JWA::X25519.send(:coerce_scalar_fe!, input_scalar)
      input_u_coordinate  = JOSE::JWA::X25519.send(:coerce_coordinate_fe!, input_u_coordinate)
      output_u_coordinate = JOSE::JWA::X25519.send(:coerce_coordinate_fe!, output_u_coordinate)
      assert_equal output_u_coordinate, JOSE::JWA::X25519.curve25519(input_scalar, input_u_coordinate)
    end
  end

  def test_curve25519_rfc7748_x25519
    vectors = [
      [
        hexstr2bin("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"), # Alice's private key, f
        hexstr2bin("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"), # Alice's public key, X25519(f, 9)
        hexstr2bin("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"), # Bob's private key, g
        hexstr2bin("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"), # Bob's public key, X25519(g, 9)
        hexstr2bin("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")  # Their shared secret, K
      ]
    ]
    vectors.each do |(alice_sk, alice_pk, bob_sk, bob_pk, k)|
      assert_equal k, JOSE::JWA::X25519.shared_secret(alice_pk, bob_sk)
      assert_equal k, JOSE::JWA::X25519.shared_secret(bob_pk, alice_sk)
    end
  end

  def test_curve448_rfc7748_curve448
    vectors = [
      [
        599189175373896402783756016145213256157230856085026129926891459468622403380588640249457727683869421921443004045221642549886377526240828, # Input scalar
        382239910814107330116229961234899377031416365240571325148346555922438025162094455820962429142971339584360034337310079791515452463053830, # Input u-coordinate
        hexstr2lint("ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239fe14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f")          # Output u-coordinate
      ],
      [
        633254335906970592779259481534862372382525155252028961056404001332122152890562527156973881968934311400345568203929409663925541994577184, # Input scalar
        622761797758325444462922068431234180649590390024811299761625153767228042600197997696167956134770744996690267634159427999832340166786063, # Input u-coordinate
        hexstr2lint("884a02576239ff7a2f2f63b2db6a9ff37047ac13568e1e30fe63c4a7ad1b3ee3a5700df34321d62077e63633c575c1c954514e99da7c179d")          # Output u-coordinate
      ]
    ]
    vectors.each do |(input_scalar, input_u_coordinate, output_u_coordinate)|
      input_scalar        = JOSE::JWA::X448.send(:coerce_scalar_fe!, input_scalar)
      input_u_coordinate  = JOSE::JWA::X448.send(:coerce_coordinate_fe!, input_u_coordinate)
      output_u_coordinate = JOSE::JWA::X448.send(:coerce_coordinate_fe!, output_u_coordinate)
      assert_equal output_u_coordinate, JOSE::JWA::X448.curve448(input_scalar, input_u_coordinate)
    end
  end

  def test_curve448_rfc7748_x448
    vectors = [
      [
        hexstr2bin("9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b"), # Alice's private key, f
        hexstr2bin("9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0"), # Alice's public key, X448(f, 9)
        hexstr2bin("1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d"), # Bob's private key, g
        hexstr2bin("3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609"), # Bob's public key, X448(g, 9)
        hexstr2bin("07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a449a5037514a879d")  # Their shared secret, K
      ]
    ]
    vectors.each do |(alice_sk, alice_pk, bob_sk, bob_pk, k)|
      assert_equal k, JOSE::JWA::X448.shared_secret(alice_pk, bob_sk)
      assert_equal k, JOSE::JWA::X448.shared_secret(bob_pk, alice_sk)
    end
  end

private
  def hexstr2bin(hexstr)
    return [hexstr].pack('H*')
  end

  def hexstr2lint(hexstr)
    return OpenSSL::BN.new(hexstr2bin(hexstr).reverse, 2).to_i
  end
end
