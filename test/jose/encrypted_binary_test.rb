require 'test_helper'

class JOSE::EncryptedBinaryTest < Minitest::Test

  JWE_CIPHERTEXT    = [188,214,210,224].pack('C*')
  JWE_ENCRYPTED_KEY = [14,231,107,199,103,156,121,95,43,22,142,158,94,145,83,27,213,67,193,44,97,147,72,246].pack('C*')
  JWE_IV            = [174,216,130,100,105,220,105,179,179,188,78,9].pack('C*')
  JWE_PROTECTED     = {"alg"=>"A128KW", "enc"=>"A128GCM"}
  JWE_TAG           = [195,86,85,0,75,68,49,55,227,119,218,116,24,15,69,116].pack('C*')
  ENCRYPTED_BINARY  = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4R0NNIn0.Dudrx2eceV8rFo6eXpFTG9VDwSxhk0j2.rtiCZGncabOzvE4J.vNbS4A.w1ZVAEtEMTfjd9p0GA9FdA"
  ENCRYPTED_MAP     = {"iv"=>"rtiCZGncabOzvE4J", "tag"=>"w1ZVAEtEMTfjd9p0GA9FdA", "ciphertext"=>"vNbS4A", "encrypted_key"=>"Dudrx2eceV8rFo6eXpFTG9VDwSxhk0j2", "protected"=>"eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4R0NNIn0"}

  def test_expand
    encrypted_binary = JOSE::EncryptedBinary.new(ENCRYPTED_BINARY)
    encrypted_map    = JOSE::EncryptedMap.new(ENCRYPTED_MAP)
    assert_equal encrypted_map, encrypted_binary.expand
  end

  def test_peek_ciphertext
    encrypted_binary = JOSE::EncryptedBinary.new(ENCRYPTED_BINARY)
    assert_equal JWE_CIPHERTEXT, encrypted_binary.peek_ciphertext
  end

  def test_peek_encrypted_key
    encrypted_binary = JOSE::EncryptedBinary.new(ENCRYPTED_BINARY)
    assert_equal JWE_ENCRYPTED_KEY, encrypted_binary.peek_encrypted_key
  end

  def test_peek_iv
    encrypted_binary = JOSE::EncryptedBinary.new(ENCRYPTED_BINARY)
    assert_equal JWE_IV, encrypted_binary.peek_iv
  end

  def test_peek_protected
    encrypted_binary = JOSE::EncryptedBinary.new(ENCRYPTED_BINARY)
    assert_equal JWE_PROTECTED, encrypted_binary.peek_protected
  end

  def test_peek_tag
    encrypted_binary = JOSE::EncryptedBinary.new(ENCRYPTED_BINARY)
    assert_equal JWE_TAG, encrypted_binary.peek_tag
  end

end
