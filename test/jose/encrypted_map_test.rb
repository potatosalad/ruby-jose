require 'test_helper'

class JOSE::EncryptedMapTest < Minitest::Test

  ENCRYPTED_BINARY = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4R0NNIn0.Dudrx2eceV8rFo6eXpFTG9VDwSxhk0j2.rtiCZGncabOzvE4J.vNbS4A.w1ZVAEtEMTfjd9p0GA9FdA"
  ENCRYPTED_MAP    = {"iv"=>"rtiCZGncabOzvE4J", "tag"=>"w1ZVAEtEMTfjd9p0GA9FdA", "ciphertext"=>"vNbS4A", "encrypted_key"=>"Dudrx2eceV8rFo6eXpFTG9VDwSxhk0j2", "protected"=>"eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4R0NNIn0"}

  def test_compact
    encrypted_binary = JOSE::EncryptedBinary.new(ENCRYPTED_BINARY)
    encrypted_map    = JOSE::EncryptedMap.new(ENCRYPTED_MAP)
    assert_equal encrypted_binary, encrypted_map.compact
  end

end
