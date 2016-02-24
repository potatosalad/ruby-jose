module JOSE
  module JWA

    extend self

    UCHAR_PACK = 'C*'.freeze
    ZERO_PAD = [0].pack('C').force_encoding('BINARY').freeze

    def constant_time_compare(a, b)
      return false if a.empty? || b.empty? || a.bytesize != b.bytesize
      l = a.unpack "C#{a.bytesize}"

      res = 0
      b.each_byte { |byte| res |= byte ^ l.shift }
      return res == 0
    end

    def exor(a, b)
      a = a.to_bn if a.respond_to?(:to_bn)
      b = b.to_bn if b.respond_to?(:to_bn)
      a = a.to_s(2) if a.is_a?(OpenSSL::BN)
      b = b.to_s(2) if b.is_a?(OpenSSL::BN)
      as = a.bytesize
      bs = b.bytesize
      a.ljust!(bs, ZERO_PAD) if as < bs
      b.ljust!(as, ZERO_PAD) if bs < as
      return OpenSSL::BN.new(a.unpack(UCHAR_PACK).zip(b.unpack(UCHAR_PACK)).map do |ac,bc|
        next (ac ^ bc)
      end.reverse.pack(UCHAR_PACK), 2)
    end

  end
end

require 'jose/jwa/field_element'

require 'jose/jwa/aes_kw'
require 'jose/jwa/concat_kdf'
require 'jose/jwa/pkcs1'
require 'jose/jwa/pkcs7'
require 'jose/jwa/x25519'
require 'jose/jwa/x448'
