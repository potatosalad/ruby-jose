require 'test_helper'

class JOSE::JWA::ConcatKDFTest < Minitest::Test

  def test_nist_800_56a
    vectors = [
      # See https://tools.ietf.org/html/rfc7518#appendix-C
      [
        'SHA256',
        [158,86,217,29,129,113,53,211,114,131,66,131,191,132,38,156,251,49,110,163,218,128,106,72,246,218,167,121,140,254,144,196].pack('C*'),
        [
          'A128GCM',
          'Alice',
          'Bob',
          [0,0,0,128].pack('C*'),
          ''
        ],
        128,
        [86,170,141,234,248,35,109,32,92,34,40,205,113,167,16,26].pack('C*')
      ],
      # See https://bitbucket.org/b_c/jose4j/src/cb968fdb10bdef6ecedf279b030f9b3af59f5e8e/src/test/java/org/jose4j/jwe/kdf/ConcatKeyDerivationFunctionTest.java
      [
        'SHA256',
        JOSE.urlsafe_decode64('Sq8rGLm4rEtzScmnSsY5r1n-AqBl_iBU8FxN80Uc0S0'),
        [
          'A256CBC-HS512',
          '',
          '',
          [0,0,2,0].pack('C*'),
          ''
        ],
        512,
        JOSE.urlsafe_decode64('pgs50IOZ6BxfqvTSie4t9OjWxGr4whiHo1v9Dti93CRiJE2PP60FojLatVVrcjg3BxpuFjnlQxL97GOwAfcwLA')
      ],
      [
        'SHA256',
        JOSE.urlsafe_decode64('LfkHot2nGTVlmfxbgxQfMg'),
        [
          'A128CBC-HS256',
          '',
          '',
          [0,0,1,0].pack('C*'),
          ''
        ],
        256,
        JOSE.urlsafe_decode64('vphyobtvExGXF7TaOvAkx6CCjHQNYamP2ET8xkhTu-0')
      ],
      [
        'SHA256',
        JOSE.urlsafe_decode64('LfkHot2nGTVlmfxbgxQfMg'),
        [
          'A128CBC-HS256',
          '',
          '',
          [0,0,1,0].pack('C*'),
          ''
        ],
        nil,
        JOSE.urlsafe_decode64('vphyobtvExGXF7TaOvAkx6CCjHQNYamP2ET8xkhTu-0')
      ],
      [
        'SHA256',
        JOSE.urlsafe_decode64('KSDnQpf2iurUsAbcuI4YH-FKfk2gecN6cWHTYlBzrd8'),
        [
          'meh',
          'Alice',
          'Bob',
          [0,0,4,0].pack('C*'),
          ''
        ],
        1024,
        JOSE.urlsafe_decode64('yRbmmZJpxv3H1aq3FgzESa453frljIaeMz6pt5rQZ4Q5Hs-4RYoFRXFh_qBsbTjlsj8JxIYTWj-cp5LKtgi1fBRsf_5yTEcLDv4pKH2fNxjbEOKuVVDWA1_Qv2IkEC0_QSi3lSSELcJaNX-hDG8occ7oQv-w8lg6lLJjg58kOes')
      ],
      [
        'SHA256',
        JOSE.urlsafe_decode64('zp9Hot2noTVlmfxbkXqfn1'),
        [
          'A192CBC-HS384',
          '',
          '',
          [0,0,1,128].pack('C*'),
          ''
        ],
        384,
        JOSE.urlsafe_decode64('SNOvl6h5iSYWJ_EhlnvK8o6om9iyR8HkKMQtQYGkYKkVY0HFMleoUm-H6-kLz8sW')
      ]
    ]
    vectors.each_with_index do |(hash, z, other_info, key_data_len, derived_key), index|
      assert_equal derived_key, JOSE::JWA::ConcatKDF.kdf(hash, z, other_info, key_data_len), "failed test vector ##{index + 1}"
    end
  end

end
