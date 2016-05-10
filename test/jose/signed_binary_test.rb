require 'test_helper'

class JOSE::SignedBinaryTest < Minitest::Test

  JWS_PAYLOAD   = "test"
  JWS_PROTECTED = {"alg"=>"Ed25519"}
  JWS_SIGNATURE = [157,213,165,111,245,154,131,160,81,46,72,72,41,184,132,228,217,202,43,74,31,11,16,78,227,61,65,237,11,69,3,28,230,201,94,174,245,10,198,214,170,49,244,201,89,43,178,221,127,175,31,50,209,226,242,234,138,90,223,145,77,157,161,1].pack('C*')
  SIGNED_BINARY = "eyJhbGciOiJFZDI1NTE5In0.dGVzdA.ndWlb_Wag6BRLkhIKbiE5NnKK0ofCxBO4z1B7QtFAxzmyV6u9QrG1qox9MlZK7Ldf68fMtHi8uqKWt-RTZ2hAQ"
  SIGNED_MAP    = {"signature"=>"ndWlb_Wag6BRLkhIKbiE5NnKK0ofCxBO4z1B7QtFAxzmyV6u9QrG1qox9MlZK7Ldf68fMtHi8uqKWt-RTZ2hAQ", "payload"=>"dGVzdA", "protected"=>"eyJhbGciOiJFZDI1NTE5In0"}

  def test_expand
    signed_binary = JOSE::SignedBinary.new(SIGNED_BINARY)
    signed_map    = JOSE::SignedMap.new(SIGNED_MAP)
    assert_equal signed_map, signed_binary.expand
  end

  def test_peek_payload
    signed_binary = JOSE::SignedBinary.new(SIGNED_BINARY)
    assert_equal JWS_PAYLOAD, signed_binary.peek_payload
  end

  def test_peek_protected
    signed_binary = JOSE::SignedBinary.new(SIGNED_BINARY)
    assert_equal JWS_PROTECTED, signed_binary.peek_protected
  end

  def test_peek_signature
    signed_binary = JOSE::SignedBinary.new(SIGNED_BINARY)
    assert_equal JWS_SIGNATURE, signed_binary.peek_signature
  end

end
