require 'test_helper'

class JOSE::JWETest < Minitest::Test

  def test_property_of_from
    property_of {
      Tuple.new([
        urlsafe_base64_dict(),
        choose_jwe_alg(),
        choose_jwe_enc()
      ])
    }.check { |tuple|
      object = tuple[0].merge({
        'alg' => tuple[1],
        'enc' => tuple[2]
      })
      jwe = JOSE::JWE.from(object)
      jwe_binary = JOSE::JWE.to_binary(jwe)
      jwe_map = JOSE::JWE.to_map(jwe)
      assert_equal jwe, JOSE::JWE.from(jwe)
      assert_equal jwe, JOSE::JWE.from(jwe_binary)
      assert_equal jwe, JOSE::JWE.from(jwe_map)
      assert_equal [jwe, jwe, jwe], JOSE::JWE.from([jwe, jwe_binary, jwe_map])
      jwe_binary_array = JOSE::JWE.to_binary([jwe])
      jwe_map_array = JOSE::JWE.to_map([jwe])
      assert_equal [jwe], JOSE::JWE.from_binary(jwe_binary_array)
      assert_equal [jwe], JOSE::JWE.from_map(jwe_map_array)
      assert_raises(ArgumentError) { JOSE::JWE.from(nil) }
      assert_raises(ArgumentError) { JOSE::JWE.from_binary(nil) }
      assert_raises(ArgumentError) { JOSE::JWE.from_map(nil) }
    }
  end

  def test_merge
    unmerged_jwe = JOSE::JWE.from({'alg' => 'dir', 'enc' => 'A128GCM'})
    binary = "{\"alg\":\"A128KW\",\"c\":\"3\"}"
    map = JOSE::Map['alg' => 'A128KW', 'c' => '3']
    jwe = JOSE::JWE.from(map.merge('enc' => 'A128GCM'))
    merged_jwe = JOSE::JWE.from({'alg' => 'A128KW', 'enc' => 'A128GCM', 'c' => '3'})
    assert_equal merged_jwe, JOSE::JWE.merge(unmerged_jwe, binary)
    assert_equal merged_jwe, JOSE::JWE.merge(unmerged_jwe, map)
    assert_equal merged_jwe, JOSE::JWE.merge(unmerged_jwe, jwe)
  end

end
