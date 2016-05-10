require 'test_helper'

class JOSE::JWSTest < Minitest::Test

  def test_property_of_from
    property_of {
      Tuple.new([
        urlsafe_base64_dict(),
        choose_jws_alg()
      ])
    }.check { |tuple|
      object = tuple[0].merge({
        'alg' => tuple[1]
      })
      jws = JOSE::JWS.from(object)
      jws_binary = JOSE::JWS.to_binary(jws)
      jws_map = JOSE::JWS.to_map(jws)
      assert_equal jws, JOSE::JWS.from(jws)
      assert_equal jws, JOSE::JWS.from(jws_binary)
      assert_equal jws, JOSE::JWS.from(jws_map)
      assert_equal [jws, jws, jws], JOSE::JWS.from([jws, jws_binary, jws_map])
      jws_binary_array = JOSE::JWS.to_binary([jws])
      jws_map_array = JOSE::JWS.to_map([jws])
      assert_equal [jws], JOSE::JWS.from_binary(jws_binary_array)
      assert_equal [jws], JOSE::JWS.from_map(jws_map_array)
      assert_raises(ArgumentError) { JOSE::JWS.from(nil) }
      assert_raises(ArgumentError) { JOSE::JWS.from_binary(nil) }
      assert_raises(ArgumentError) { JOSE::JWS.from_map(nil) }
    }
  end

  def test_merge
    unmerged_jws = JOSE::JWS.from({'alg' => 'HS256', 'a' => '1'})
    binary = "{\"alg\":\"Ed448\",\"c\":\"3\"}"
    map = JOSE::Map['alg' => 'Ed448', 'c' => '3']
    jws = JOSE::JWS.from(map)
    merged_jws = JOSE::JWS.from({'alg' => 'Ed448', 'a' => '1', 'c' => '3'})
    assert_equal merged_jws, JOSE::JWS.merge(unmerged_jws, binary)
    assert_equal merged_jws, JOSE::JWS.merge(unmerged_jws, map)
    assert_equal merged_jws, JOSE::JWS.merge(unmerged_jws, jws)
  end

end
