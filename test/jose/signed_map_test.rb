require 'test_helper'

class JOSE::SignedMapTest < Minitest::Test

  SIGNED_BINARY = "eyJhbGciOiJFZDI1NTE5In0.dGVzdA.ndWlb_Wag6BRLkhIKbiE5NnKK0ofCxBO4z1B7QtFAxzmyV6u9QrG1qox9MlZK7Ldf68fMtHi8uqKWt-RTZ2hAQ"
  SIGNED_MAP    = {"signature"=>"ndWlb_Wag6BRLkhIKbiE5NnKK0ofCxBO4z1B7QtFAxzmyV6u9QrG1qox9MlZK7Ldf68fMtHi8uqKWt-RTZ2hAQ", "payload"=>"dGVzdA", "protected"=>"eyJhbGciOiJFZDI1NTE5In0"}

  def test_compact
    signed_binary = JOSE::SignedBinary.new(SIGNED_BINARY)
    signed_map    = JOSE::SignedMap.new(SIGNED_MAP)
    assert_equal signed_binary, signed_map.compact
  end

end
