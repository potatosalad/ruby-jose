require 'test_helper'

class JOSE::JWA::Curve25519_RbNaClTest < Minitest::Test

  EdDSA_SECRET        = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0].pack('C*')
  EdDSA_SK            = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,59,106,39,188,206,182,164,45,98,163,168,208,42,111,13,115,101,50,21,119,29,226,67,166,58,192,72,161,139,89,218,41].pack('C*')
  EdDSA_PK            = [59,106,39,188,206,182,164,45,98,163,168,208,42,111,13,115,101,50,21,119,29,226,67,166,58,192,72,161,139,89,218,41].pack('C*')
  EdDSA_M             = [].pack('C*')
  Ed25519_SIGNATURE   = [143,137,91,60,175,226,201,80,96,57,208,226,166,99,130,86,128,4,103,79,232,210,55,120,80,146,228,13,106,175,72,62,79,198,1,104,112,95,49,241,1,89,97,56,206,33,170,53,124,13,50,160,100,244,35,220,62,228,170,58,191,83,248,3].pack('C*')
  Ed25519ph_SIGNATURE = [156,203,202,248,117,129,126,7,75,58,114,37,34,97,88,28,107,134,137,45,226,153,205,227,223,176,47,120,25,58,104,151,0,98,205,14,60,170,233,142,178,63,207,181,133,191,210,47,240,169,14,31,162,243,195,196,214,28,175,237,234,99,76,4].pack('C*')
  Curve25519_SECRET   = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,64].pack('C*')
  Curve25519_PUBLIC   = [47,229,125,163,71,205,98,67,21,40,218,172,95,187,41,7,48,255,246,132,175,196,207,194,237,144,153,95,88,203,59,116].pack('C*')
  Curve25519_SHARED   = [147,254,162,167,193,174,182,44,253,100,82,255,91,173,174,139,223,252,189,113,150,220,145,12,137,148,64,6,216,93,187,104].pack('C*')

  def test_supported_methods
    if JOSE::JWA::Curve25519_RbNaCl.__supported__?
      [
        [[EdDSA_PK, EdDSA_SK], :ed25519_keypair, EdDSA_SECRET],
        [EdDSA_PK, :ed25519_secret_to_public, EdDSA_SK],
        [Ed25519_SIGNATURE, :ed25519_sign, EdDSA_M, EdDSA_SK],
        [true, :ed25519_verify, Ed25519_SIGNATURE, EdDSA_M, EdDSA_PK],
        [[EdDSA_PK, EdDSA_SK], :ed25519ph_keypair, EdDSA_SECRET],
        [EdDSA_PK, :ed25519ph_secret_to_public, EdDSA_SK],
        [Ed25519ph_SIGNATURE, :ed25519ph_sign, EdDSA_M, EdDSA_SK],
        [true, :ed25519ph_verify, Ed25519ph_SIGNATURE, EdDSA_M, EdDSA_PK],
        [[Curve25519_PUBLIC, Curve25519_SECRET], :x25519_keypair, Curve25519_SECRET],
        [Curve25519_PUBLIC, :x25519_secret_to_public, Curve25519_SECRET],
        [Curve25519_SHARED, :x25519_shared_secret, Curve25519_PUBLIC, Curve25519_SECRET]
      ].each do |(expected, function, *args)|
        assert_equal expected, JOSE::JWA::Curve25519_RbNaCl.send(function, *args)
      end
    end
  end

end
