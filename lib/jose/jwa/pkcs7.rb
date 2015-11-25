module JOSE::JWA::PKCS7

  extend self

  def pad(binary)
    size = 16 - (binary.bytesize % 16)
    return [binary, *([size] * size)].pack('a*C*')
  end

  def unpad(binary)
    p = binary.getbyte(-1)
    size = binary.bytesize - p
    binary_s = StringIO.new(binary)
    result = binary_s.read(size)
    p.times do
      if binary_s.getbyte != p
        raise ArgumentError, "unrecognized padding"
      end
    end
    return result
  end

end
