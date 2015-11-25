module JOSE::JWA::ConcatKDF

  extend self

  def kdf(hash, z, other_info, key_data_len = nil)
    if hash.is_a?(String)
      hash = OpenSSL::Digest.new(hash)
    end
    if key_data_len.nil?
      key_data_len = hash.digest('').bytesize * 8
    end
    if other_info.is_a?(Array)
      algorithm_id, party_u_info, party_v_info, supp_pub_info, supp_priv_info = other_info
      supp_pub_info ||= ''
      supp_priv_info ||= ''
      other_info = [
        algorithm_id.bytesize, algorithm_id,
        party_u_info.bytesize, party_u_info,
        party_v_info.bytesize, party_v_info,
        supp_pub_info,
        supp_priv_info
      ].pack('Na*Na*Na*a*a*')
    end
    hash_len = hash.digest('').bytesize * 8
    reps = (key_data_len / hash_len.to_f).ceil
    if reps == 1
      concatenation = [ 0, 0, 0, 1, z, other_info ].pack('C4a*a*')
      derived_key = [hash.digest(concatenation).unpack('B*')[0][0...key_data_len]].pack('B*')
      return derived_key
    elsif reps > 0xFFFFFFFF
      raise ArgumentError, "too many reps"
    else
      return derive_key(hash, 1, reps, key_data_len, [z, other_info].join, '')
    end
  end

private

  def derive_key(hash, counter, reps, key_data_len, z_other_info, derived_keying_material)
    if counter == reps
      concatenation = [counter, z_other_info].pack('Na*')
      derived_key = [[derived_keying_material, hash.digest(concatenation)].join.unpack('B*')[0][0...key_data_len]].pack('B*')
      return derived_key
    else
      concatenation = [counter, z_other_info].pack('Na*')
      return derive_key(hash, counter + 1, reps, key_data_len, z_other_info, [derived_keying_material, hash.digest(concatenation)].join)
    end
  end

end
