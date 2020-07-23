module JOSE
  # JWA stands for JSON Web Algorithms which is defined in [RFC 7518](https://tools.ietf.org/html/rfc7518).
  #
  # ## Cryptographic Algorithm Fallback
  #
  # Native implementations of all cryptographic and public key algorithms
  # required by the JWA specifications are not present in current versions
  # of Ruby.
  #
  # JOSE will detect whether a specific algorithm is natively supported or not
  # and, by default, it will mark the algorithm as unsupported if a native
  # implementation is not found.
  #
  # However, JOSE also has pure Ruby versions of many of the missing algorithms
  # which can be used as a fallback by calling {JOSE.crypto_fallback= JOSE.crypto_fallback=} and
  # passing `true`.
  module JWA

    extend self

    UCHAR_PACK = 'C*'.freeze
    ZERO_PAD = [0].pack('C').force_encoding('BINARY').freeze

    # Performs a constant time comparison between two binaries to help avoid [timing attacks](https://en.wikipedia.org/wiki/Timing_attack).
    # @param [String] a
    # @param [String] b
    # @return [Boolean]
    def constant_time_compare(a, b)
      return false if a.empty? || b.empty? || a.bytesize != b.bytesize
      l = a.unpack "C#{a.bytesize}"

      res = 0
      b.each_byte { |byte| res |= byte ^ l.shift }
      return res == 0
    end

    # @!visibility private
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

    # Returns the current listing of supported JOSE algorithms.
    #
    #     !!!ruby
    #     JOSE::JWA.supports
    #     # => {:jwe=>
    #     #   {:alg=>
    #     #     ["A128GCMKW",
    #     #      "A192GCMKW",
    #     #      "A256GCMKW",
    #     #      "A128KW",
    #     #      "A192KW",
    #     #      "A256KW",
    #     #      "ECDH-ES",
    #     #      "ECDH-ES+A128KW",
    #     #      "ECDH-ES+A192KW",
    #     #      "ECDH-ES+A256KW",
    #     #      "PBES2-HS256+A128KW",
    #     #      "PBES2-HS384+A192KW",
    #     #      "PBES2-HS512+A256KW",
    #     #      "RSA1_5",
    #     #      "RSA-OAEP",
    #     #      "RSA-OAEP-256",
    #     #      "dir"],
    #     #    :enc=>
    #     #     ["A128GCM",
    #     #      "A192GCM",
    #     #      "A256GCM",
    #     #      "A128CBC-HS256",
    #     #      "A192CBC-HS384",
    #     #      "A256CBC-HS512"],
    #     #    :zip=>
    #     #     ["DEF"]},
    #     #  :jwk=>
    #     #   {:kty=>
    #     #     ["EC",
    #     #      "OKP",
    #     #      "RSA",
    #     #      "oct"],
    #     #    :kty_EC_crv=>
    #     #     ["P-256",
    #     #      "P-384",
    #     #      "P-521"],
    #     #    :kty_OKP_crv=>
    #     #     ["Ed25519",
    #     #      "Ed25519ph",
    #     #      "Ed448",
    #     #      "Ed448ph",
    #     #      "X25519",
    #     #      "X448"]},
    #     #  :jws=>
    #     #   {:alg=>
    #     #     ["Ed25519",
    #     #      "Ed25519ph",
    #     #      "Ed448",
    #     #      "Ed448ph",
    #     #      "EdDSA",
    #     #      "ES256",
    #     #      "ES384",
    #     #      "ES512",
    #     #      "HS256",
    #     #      "HS384",
    #     #      "HS512",
    #     #      "PS256",
    #     #      "PS384",
    #     #      "PS512",
    #     #      "RS256",
    #     #      "RS384",
    #     #      "RS512",
    #     #      "none"]}}
    #
    # @return [Hash]
    def supports
      jwe_enc = __jwe_enc_support_check__([
        'A128GCM',
        'A192GCM',
        'A256GCM',
        'A128CBC-HS256',
        'A192CBC-HS384',
        'A256CBC-HS512',
        'C20P',
        'XC20P'
      ])
      jwe_alg = __jwe_alg_support_check__([
        ['A128GCMKW', :block],
        ['A192GCMKW', :block],
        ['A256GCMKW', :block],
        ['A128KW', :block],
        ['A192KW', :block],
        ['A256KW', :block],
        ['C20PKW', :block],
        ['ECDH-ES', :box],
        ['ECDH-ES+A128KW', :box],
        ['ECDH-ES+A192KW', :box],
        ['ECDH-ES+A256KW', :box],
        ['PBES2-HS256+A128KW', :block],
        ['PBES2-HS384+A192KW', :block],
        ['PBES2-HS512+A256KW', :block],
        ['RSA1_5', :rsa],
        ['RSA-OAEP', :rsa],
        ['RSA-OAEP-256', :rsa],
        ['XC20PKW', :block],
        ['dir', :direct]
      ], jwe_enc)
      jwe_zip = __jwe_zip_support_check__([
        'DEF'
      ], jwe_enc)
      jwk_kty, jwk_kty_EC_crv, jwk_kty_OKP_crv = __jwk_kty_support_check__([
        ['EC', ['P-256', 'P-384', 'P-521']],
        ['OKP', ['Ed25519', 'Ed25519ph', 'Ed448', 'Ed448ph', 'X25519', 'X448']],
        'RSA',
        'oct'
      ])
      jws_alg = __jws_alg_support_check__([
        'Ed25519',
        'Ed25519ph',
        'Ed448',
        'Ed448ph',
        'EdDSA',
        'ES256',
        'ES384',
        'ES512',
        'HS256',
        'HS384',
        'HS512',
        'PS256',
        'PS384',
        'PS512',
        'RS256',
        'RS384',
        'RS512',
        'X25519',
        'X448',
        'none'
      ])
      return {
        jwe: {
          alg: jwe_alg,
          enc: jwe_enc,
          zip: jwe_zip
        },
        jwk: {
          kty: jwk_kty,
          kty_EC_crv: jwk_kty_EC_crv,
          kty_OKP_crv: jwk_kty_OKP_crv
        },
        jws: {
          alg: jws_alg
        }
      }
    end

  private

    def __jwe_enc_support_check__(encryption_algorithms)
      plain_text = SecureRandom.random_bytes(16)
      return encryption_algorithms.select do |enc|
        begin
          jwe = JOSE::JWE.from({ 'alg' => 'dir', 'enc' => enc })
          jwk = jwe.generate_key
          cipher_text = jwk.block_encrypt(plain_text).compact
          next jwk.block_decrypt(cipher_text).first == plain_text
        rescue StandardError, NotImplementedError
          next false
        end
      end
    end

    def __jwe_alg_support_check__(key_algorithms, encryption_algorithms)
      return [] if encryption_algorithms.empty?
      plain_text = SecureRandom.random_bytes(16)
      enc = encryption_algorithms[0]
      rsa = nil
      return key_algorithms.select do |(alg, strategy)|
        begin
          if strategy == :block
            jwe = JOSE::JWE.from({ 'alg' => alg, 'enc' => enc })
            jwk = jwe.generate_key
            cipher_text = jwk.block_encrypt(plain_text).compact
            next jwk.block_decrypt(cipher_text).first == plain_text
          elsif strategy == :box
            jwe = JOSE::JWE.from({ 'alg' => alg, 'enc' => enc })
            send_jwk = jwe.generate_key
            recv_jwk = jwe.generate_key
            cipher_text = recv_jwk.box_encrypt(plain_text, send_jwk).compact
            next recv_jwk.box_decrypt(cipher_text).first == plain_text
          elsif strategy == :rsa
            rsa ||= JOSE::JWK.generate_key([:rsa, 2048])
            cipher_text = rsa.block_encrypt(plain_text, { 'alg' => alg, 'enc' => enc }).compact
            next rsa.block_decrypt(cipher_text).first == plain_text
          elsif strategy == :direct
            next true
          else
            next false
          end
        rescue StandardError, NotImplementedError
          next false
        end
      end.transpose.first
    end

    def __jwe_zip_support_check__(zip_algorithms, encryption_algorithms)
      return [] if encryption_algorithms.empty?
      plain_text = SecureRandom.random_bytes(16)
      alg = 'dir'
      enc = encryption_algorithms[0]
      return zip_algorithms.select do |zip|
        begin
          jwe = JOSE::JWE.from({ 'alg' => alg, 'enc' => enc, 'zip' => zip })
          jwk = jwe.generate_key
          cipher_text = jwk.block_encrypt(plain_text, jwe).compact
          next jwk.block_decrypt(cipher_text).first == plain_text
        rescue StandardError, NotImplementedError
          next false
        end
      end
    end

    def __jwk_kty_support_check__(key_types)
      kty = []
      kty_EC_crv = []
      kty_OKP_crv = []
      key_types.each do |(key_type, curves)|
        case key_type
        when 'EC'
          curves.each do |curve|
            begin
              JOSE::JWK.generate_key([:ec, curve])
              kty_EC_crv.push(curve)
            rescue StandardError, NotImplementedError
              next
            end
          end
          kty.push(key_type) if not kty_EC_crv.empty?
        when 'OKP'
          curves.each do |curve|
            begin
              JOSE::JWK.generate_key([:okp, curve.to_sym])
              kty_OKP_crv.push(curve)
            rescue StandardError, NotImplementedError
              next
            end
          end
          kty.push(key_type) if not kty_OKP_crv.empty?
        when 'RSA'
          begin
            JOSE::JWK.generate_key([:rsa, 1024])
            kty.push(key_type)
          rescue StandardError, NotImplementedError
            # do nothing
          end
        when 'oct'
          begin
            JOSE::JWK.generate_key([:oct, 8])
            kty.push(key_type)
          rescue StandardError, NotImplementedError
            # do nothing
          end
        end
      end
      return kty, kty_EC_crv, kty_OKP_crv
    end

    def __jws_alg_support_check__(signature_algorithms)
      plain_text = SecureRandom.random_bytes(16)
      rsa = nil
      return signature_algorithms.select do |alg|
        begin
          jwk = nil
          jwk ||= JOSE::JWK.generate_key([:oct, 0]).merge({ 'alg' => alg, 'use' => 'sig' }) if alg == 'none'
          jwk ||= (rsa ||= JOSE::JWK.generate_key([:rsa, 2048])).merge({ 'alg' => alg, 'use' => 'sig' }) if alg.start_with?('RS') or alg.start_with?('PS')
          jwk ||= JOSE::JWS.generate_key({ 'alg' => alg })
          signed_text = jwk.sign(plain_text).compact
          next jwk.verify_strict(signed_text, [alg]).first
        rescue StandardError, NotImplementedError
          next false
        end
      end
    end

  end
end

require 'jose/jwa/field_element'
require 'jose/jwa/edwards_point'
require 'jose/jwa/sha3'

require 'jose/jwa/aes_kw'
require 'jose/jwa/concat_kdf'
require 'jose/jwa/curve25519'
require 'jose/jwa/curve448'
require 'jose/jwa/pkcs1'
require 'jose/jwa/pkcs7'
require 'jose/jwa/xchacha20poly1305'
