require 'hamster/vector'

# Immutable Set structure based on `Hamster::Vector`.
class JOSE::JWK::Set < Hamster::Vector

  def self.from_map(fields)
    if fields['keys'].is_a?(Array)
      keys = fields['keys'].map do |key|
        next JOSE::JWK.from(key)
      end
      return JOSE::JWK::Set.new(keys), fields.except('keys')
    end
    raise ArgumentError, "invalid 'OKP' crv 'X448' JWK"
  end

  def to_map(fields)
    jwks = self.map do |key|
      next key.to_map
    end.to_a
    return fields.put('keys', jwks)
  end

end
