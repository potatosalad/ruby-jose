module JOSE
  module JWA

    extend self

    def constant_time_compare(a, b)
      return false if a.empty? || b.empty? || a.bytesize != b.bytesize
      l = a.unpack "C#{a.bytesize}"

      res = 0
      b.each_byte { |byte| res |= byte ^ l.shift }
      return res == 0
    end

  end
end

require 'jose/jwa/aes_kw'
require 'jose/jwa/concat_kdf'
require 'jose/jwa/pkcs1'
require 'jose/jwa/pkcs7'
