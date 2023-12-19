require 'test_helper'

class JOSETest < Minitest::Test
  def test_that_it_has_a_version_number
    refute_nil ::JOSE::VERSION
  end

  # JSON Web Encryption (JWE)
  # A.1.  Example JWE using RSAES-OAEP and AES GCM
  # https://tools.ietf.org/html/rfc7516#appendix-A.1
  def test_jwe_a_1
    # A.1
    a_1_txt = [84,104,101,32,116,114,117,101,32,115,105,103,110,32,111,102,32,105,110,116,101,108,108,105,103,101,110,99,101,32,105,115,32,110,111,116,32,107,110,111,119,108,101,100,103,101,32,98,117,116,32,105,109,97,103,105,110,97,116,105,111,110,46].pack('C*')
    # A.1.1
    a_1_1_jwe_json = "{\"alg\":\"RSA-OAEP\",\"enc\":\"A256GCM\"}"
    a_1_1_jwe_json_b64 = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ"
    a_1_1_jwe_map = JOSE.decode(a_1_1_jwe_json)
    a_1_1_jwe = JOSE::JWE.from_binary(a_1_1_jwe_json)
    assert_equal a_1_1_jwe_map, a_1_1_jwe.to_map
    assert_equal a_1_1_jwe_json_b64, JOSE.urlsafe_encode64(a_1_1_jwe.to_binary)
    # A.1.2
    a_1_2_cek = [177,161,244,128,84,143,225,115,63,180,3,255,107,154,212,246,138,7,110,91,112,46,34,105,47,130,203,46,122,234,64,252].pack('C*')
    # A.1.3
    a_1_3_jwk_json = "{\"kty\":\"RSA\",\"n\":\"oahUIoWw0K0usKNuOR6H4wkf4oBUXHTxRvgb48E-BVvxkeDNjbC4he8rUWcJoZmds2h7M70imEVhRU5djINXtqllXI4DFqcI1DgjT9LewND8MW2Krf3Spsk_ZkoFnilakGygTwpZ3uesH-PFABNIUYpOiN15dsQRkgr0vEhxN92i2asbOenSZeyaxziK72UwxrrKoExv6kc5twXTq4h-QChLOln0_mtUZwfsRaMStPs6mS6XrgxnxbWhojf663tuEQueGC-FCMfra36C9knDFGzKsNa7LZK2djYgyD3JR_MB_4NUJW_TqOQtwHYbxevoJArm-L5StowjzGy-_bq6Gw\",\"e\":\"AQAB\",\"d\":\"kLdtIj6GbDks_ApCSTYQtelcNttlKiOyPzMrXHeI-yk1F7-kpDxY4-WY5NWV5KntaEeXS1j82E375xxhWMHXyvjYecPT9fpwR_M9gV8n9Hrh2anTpTD93Dt62ypW3yDsJzBnTnrYu1iwWRgBKrEYY46qAZIrA2xAwnm2X7uGR1hghkqDp0Vqj3kbSCz1XyfCs6_LehBwtxHIyh8Ripy40p24moOAbgxVw3rxT_vlt3UVe4WO3JkJOzlpUf-KTVI2Ptgm-dARxTEtE-id-4OJr0h-K-VFs3VSndVTIznSxfyrj8ILL6MG_Uv8YAu7VILSB3lOW085-4qE3DzgrTjgyQ\",\"p\":\"1r52Xk46c-LsfB5P442p7atdPUrxQSy4mti_tZI3Mgf2EuFVbUoDBvaRQ-SWxkbkmoEzL7JXroSBjSrK3YIQgYdMgyAEPTPjXv_hI2_1eTSPVZfzL0lffNn03IXqWF5MDFuoUYE0hzb2vhrlN_rKrbfDIwUbTrjjgieRbwC6Cl0\",\"q\":\"wLb35x7hmQWZsWJmB_vle87ihgZ19S8lBEROLIsZG4ayZVe9Hi9gDVCOBmUDdaDYVTSNx_8Fyw1YYa9XGrGnDew00J28cRUoeBB_jKI1oma0Orv1T9aXIWxKwd4gvxFImOWr3QRL9KEBRzk2RatUBnmDZJTIAfwTs0g68UZHvtc\",\"dp\":\"ZK-YwE7diUh0qR1tR7w8WHtolDx3MZ_OTowiFvgfeQ3SiresXjm9gZ5KLhMXvo-uz-KUJWDxS5pFQ_M0evdo1dKiRTjVw_x4NyqyXPM5nULPkcpU827rnpZzAJKpdhWAgqrXGKAECQH0Xt4taznjnd_zVpAmZZq60WPMBMfKcuE\",\"dq\":\"Dq0gfgJ1DdFGXiLvQEZnuKEN0UUmsJBxkjydc3j4ZYdBiMRAy86x0vHCjywcMlYYg4yoC4YZa9hNVcsjqA3FeiL19rk8g6Qn29Tt0cj8qqyFpz9vNDBUfCAiJVeESOjJDZPYHdHY8v1b-o-Z2X5tvLx-TCekf7oxyeKDUqKWjis\",\"qi\":\"VIMpMYbPf47dT1w_zDUXfPimsSegnMOA1zTaX7aGk_8urY6R8-ZW1FxU7AlWAyLWybqq6t16VFd7hQd0y6flUK4SlOydB61gwanOsXGOAOv82cHq0E3eL4HrtZkUuKvnPrMnsUUFlfUdybVzxyjz9JF_XyaY14ardLSjf4L_FNY\"}"
    a_1_3_cek_encrypted = [56,163,154,192,58,53,222,4,105,218,136,218,29,94,203,22,150,92,129,94,211,232,53,89,41,60,138,56,196,216,82,98,168,76,37,73,70,7,36,8,191,100,136,196,244,220,145,158,138,155,4,117,141,230,199,247,173,45,182,214,74,177,107,211,153,11,205,196,171,226,162,128,171,182,13,237,239,99,193,4,91,219,121,223,107,167,61,119,228,173,156,137,134,200,80,219,74,253,56,185,91,177,34,158,89,154,205,96,55,18,138,43,96,218,215,128,124,75,138,243,85,25,109,117,140,26,155,249,67,167,149,231,100,6,41,65,214,251,232,87,72,40,182,149,154,168,31,193,126,215,89,28,111,219,125,182,139,235,195,197,23,234,55,58,63,180,68,202,206,149,75,205,248,176,67,39,178,60,98,193,32,238,122,96,158,222,57,183,111,210,55,188,215,206,180,166,150,166,106,250,55,229,72,40,69,214,216,104,23,40,135,212,28,127,41,80,175,174,168,115,171,197,89,116,92,103,246,83,216,182,176,84,37,147,35,45,219,172,99,226,233,73,37,124,42,72,49,242,35,127,184,134,117,114,135,206].pack('C*')
    a_1_3_cek_encrypted_b64 = "OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGeipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDbSv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaVmqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je81860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi6UklfCpIMfIjf7iGdXKHzg"
    a_1_3_jwk_map = JOSE.decode(a_1_3_jwk_json)
    a_1_3_jwk = JOSE::JWK.from_binary(a_1_3_jwk_json)
    assert_equal a_1_3_jwk_map, a_1_3_jwk.to_map
    assert_equal a_1_3_cek_encrypted_b64, JOSE.urlsafe_encode64(a_1_3_cek_encrypted)
    # A.1.4
    a_1_4_iv = [227,197,117,252,2,219,233,68,180,225,77,219].pack('C*')
    a_1_4_iv_b64 = "48V1_ALb6US04U3b"
    assert_equal a_1_4_iv_b64, JOSE.urlsafe_encode64(a_1_4_iv)
    # A.1.5
    a_1_5_aad = [101,121,74,104,98,71,99,105,79,105,74,83,85,48,69,116,84,48,70,70,85,67,73,115,73,109,86,117,89,121,73,54,73,107,69,121,78,84,90,72,81,48,48,105,102,81].pack('C*')
    assert_equal a_1_5_aad, a_1_1_jwe_json_b64
    # A.1.6
    a_1_6_txt_cipher = [229,236,166,241,53,191,115,196,174,43,73,109,39,122,233,96,140,206,120,52,51,237,48,11,190,219,186,80,111,104,50,142,47,167,59,61,181,127,196,21,40,82,242,32,123,143,168,226,73,216,176,144,138,247,106,60,16,205,160,109,64,63,192].pack('C*')
    a_1_6_txt_tag = [92,80,104,49,133,25,161,215,173,101,219,211,136,91,210,145].pack('C*')
    a_1_6_txt_cipher_b64 = "5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_A"
    a_1_6_txt_tag_b64 = "XFBoMYUZodetZdvTiFvSkQ"
    assert_equal a_1_6_txt_cipher_b64, JOSE.urlsafe_encode64(a_1_6_txt_cipher)
    assert_equal a_1_6_txt_tag_b64, JOSE.urlsafe_encode64(a_1_6_txt_tag)
    # A.1.7
    a_1_7_jwe_compact = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGeipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDbSv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaVmqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je81860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi6UklfCpIMfIjf7iGdXKHzg.48V1_ALb6US04U3b.5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_A.XFBoMYUZodetZdvTiFvSkQ"
    a_1_7_txt, a_1_7_jwe = JOSE::JWE.block_decrypt(a_1_3_jwk, a_1_7_jwe_compact)
    assert_equal a_1_txt, a_1_7_txt
    assert_equal a_1_1_jwe, a_1_7_jwe
    # Roundtrip test
    a_1_7_map = JOSE::JWE.block_encrypt(a_1_3_jwk, a_1_txt, a_1_1_jwe, a_1_2_cek, a_1_4_iv)
    a_1_7_txt, a_1_7_jwe = JOSE::JWE.block_decrypt(a_1_3_jwk, a_1_7_map)
    assert_equal a_1_txt, a_1_7_txt
    assert_equal a_1_1_jwe, a_1_7_jwe
  end

  # JSON Web Encryption (JWE)
  # A.2.  Example JWE using RSAES-PKCS1-v1_5 and AES_128_CBC_HMAC_SHA_256
  # https://tools.ietf.org/html/rfc7516#appendix-A.2
  def test_jwe_a_2
    # A.2
    a_2_txt = [76,105,118,101,32,108,111,110,103,32,97,110,100,32,112,114,111,115,112,101,114,46].pack('C*')
    # A.2.1
    a_2_1_jwe_json = "{\"alg\":\"RSA1_5\",\"enc\":\"A128CBC-HS256\"}"
    a_2_1_jwe_json_b64 = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0"
    a_2_1_jwe_map = JOSE.decode(a_2_1_jwe_json)
    a_2_1_jwe = JOSE::JWE.from_binary(a_2_1_jwe_json)
    assert_equal a_2_1_jwe_map, a_2_1_jwe.to_map
    assert_equal a_2_1_jwe_json_b64, JOSE.urlsafe_encode64(a_2_1_jwe.to_binary)
    # A.2.2
    a_2_2_cek = [4,211,31,197,84,157,252,254,11,100,157,250,63,170,106,206,107,124,212,45,111,107,9,219,200,177,0,240,143,156,44,207].pack('C*')
    # A.2.3
    a_2_3_jwk_json = "{\"kty\":\"RSA\",\"n\":\"sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1WlUzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDprecbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBIY2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw\",\"e\":\"AQAB\",\"d\":\"VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-rynq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-KyvjT1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ\",\"p\":\"9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEPkrdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM\",\"q\":\"uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-yBhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0\",\"dp\":\"w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuvngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcraHawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs\",\"dq\":\"o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU\",\"qi\":\"eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlCtUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZB9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo\"}"
    a_2_3_cek_encrypted = [80,104,72,58,11,130,236,139,132,189,255,205,61,86,151,176,99,40,44,233,176,189,205,70,202,169,72,40,226,181,156,223,120,156,115,232,150,209,145,133,104,112,237,156,116,250,65,102,212,210,103,240,177,61,93,40,71,231,223,226,240,157,15,31,150,89,200,215,198,203,108,70,117,66,212,238,193,205,23,161,169,218,243,203,128,214,127,253,215,139,43,17,135,103,179,220,28,2,212,206,131,158,128,66,62,240,78,186,141,125,132,227,60,137,43,31,152,199,54,72,34,212,115,11,152,101,70,42,219,233,142,66,151,250,126,146,141,216,190,73,50,177,146,5,52,247,28,197,21,59,170,247,181,89,131,241,169,182,246,99,15,36,102,166,182,172,197,136,230,120,60,58,219,243,149,94,222,150,154,194,110,227,225,112,39,89,233,112,207,211,241,124,174,69,221,179,107,196,225,127,167,112,226,12,242,16,24,28,120,182,244,213,244,153,194,162,69,160,244,248,63,165,141,4,207,249,193,79,131,0,169,233,127,167,101,151,125,56,112,111,248,29,232,90,29,147,110,169,146,114,165,204,71,136,41,252].pack('C*')
    a_2_3_cek_encrypted_b64 = "UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-kFm1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKxGHZ7PcHALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3YvkkysZIFNPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPhcCdZ6XDP0_F8rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPgwCp6X-nZZd9OHBv-B3oWh2TbqmScqXMR4gp_A"
    a_2_3_jwk_map = JOSE.decode(a_2_3_jwk_json)
    a_2_3_jwk = JOSE::JWK.from_binary(a_2_3_jwk_json)
    assert_equal a_2_3_jwk_map, a_2_3_jwk.to_map
    assert_equal a_2_3_cek_encrypted_b64, JOSE.urlsafe_encode64(a_2_3_cek_encrypted)
    # A.2.4
    a_2_4_iv = [3,22,60,12,43,67,104,105,108,108,105,99,111,116,104,101].pack('C*')
    a_2_4_iv_b64 = "AxY8DCtDaGlsbGljb3RoZQ"
    assert_equal a_2_4_iv_b64, JOSE.urlsafe_encode64(a_2_4_iv)
    # A.2.5
    a_2_5_aad = [101,121,74,104,98,71,99,105,79,105,74,83,85,48,69,120,88,122,85,105,76,67,74,108,98,109,77,105,79,105,74,66,77,84,73,52,81,48,74,68,76,85,104,84,77,106,85,50,73,110,48].pack('C*')
    assert_equal a_2_5_aad, a_2_1_jwe_json_b64
    # A.2.6
    a_2_6_txt_cipher = [40,57,83,181,119,33,133,148,198,185,243,24,152,230,6,75,129,223,127,19,210,82,183,230,168,33,215,104,143,112,56,102].pack('C*')
    a_2_6_txt_tag = [246,17,244,190,4,95,98,3,231,0,115,157,242,203,100,191].pack('C*')
    a_2_6_txt_cipher_b64 = "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY"
    a_2_6_txt_tag_b64 = "9hH0vgRfYgPnAHOd8stkvw"
    assert_equal a_2_6_txt_cipher_b64, JOSE.urlsafe_encode64(a_2_6_txt_cipher)
    assert_equal a_2_6_txt_tag_b64, JOSE.urlsafe_encode64(a_2_6_txt_tag)
    # A.2.7
    a_2_7_jwe_compact = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-kFm1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKxGHZ7PcHALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3YvkkysZIFNPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPhcCdZ6XDP0_F8rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPgwCp6X-nZZd9OHBv-B3oWh2TbqmScqXMR4gp_A.AxY8DCtDaGlsbGljb3RoZQ.KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.9hH0vgRfYgPnAHOd8stkvw"
    a_2_7_txt, a_2_7_jwe = JOSE::JWE.block_decrypt(a_2_3_jwk, a_2_7_jwe_compact)
    assert_equal a_2_txt, a_2_7_txt
    assert_equal a_2_1_jwe, a_2_7_jwe
    # Roundtrip test
    a_2_7_map = JOSE::JWE.block_encrypt(a_2_3_jwk, a_2_txt, a_2_1_jwe, a_2_2_cek, a_2_4_iv)
    a_2_7_txt, a_2_7_jwe = JOSE::JWE.block_decrypt(a_2_3_jwk, a_2_7_map)
    assert_equal a_2_txt, a_2_7_txt
    assert_equal a_2_1_jwe, a_2_7_jwe
  end

  # JSON Web Encryption (JWE)
  # A.3.  Example JWE Using AES Key Wrap and AES_128_CBC_HMAC_SHA_256
  # https://tools.ietf.org/html/rfc7516#appendix-A.3
  def test_jwe_a_3
    # A.3
    a_3_txt = [76,105,118,101,32,108,111,110,103,32,97,110,100,32,112,114,111,115,112,101,114,46].pack('C*')
    # A.3.1
    a_3_1_jwe_json = "{\"alg\":\"A128KW\",\"enc\":\"A128CBC-HS256\"}"
    a_3_1_jwe_json_b64 = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0"
    a_3_1_jwe_map = JOSE.decode(a_3_1_jwe_json)
    a_3_1_jwe = JOSE::JWE.from_binary(a_3_1_jwe_json)
    assert_equal a_3_1_jwe_map, a_3_1_jwe.to_map
    assert_equal a_3_1_jwe_json_b64, JOSE.urlsafe_encode64(a_3_1_jwe.to_binary)
    # A.3.2
    a_3_2_cek = [4,211,31,197,84,157,252,254,11,100,157,250,63,170,106,206,107,124,212,45,111,107,9,219,200,177,0,240,143,156,44,207].pack('C*')
    # A.3.3
    a_3_3_jwk_json = "{\"kty\":\"oct\",\"k\":\"GawgguFyGrWKav7AX4VKUg\"}"
    a_3_3_cek_encrypted = [232,160,123,211,183,76,245,132,200,128,123,75,190,216,22,67,201,138,193,186,9,91,122,31,246,90,28,139,57,3,76,124,193,11,98,37,173,61,104,57].pack('C*')
    a_3_3_cek_encrypted_b64 = "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ"
    a_3_3_jwk_map = JOSE.decode(a_3_3_jwk_json)
    a_3_3_jwk = JOSE::JWK.from_binary(a_3_3_jwk_json)
    assert_equal a_3_3_jwk_map, a_3_3_jwk.to_map
    assert_equal a_3_3_cek_encrypted_b64, JOSE.urlsafe_encode64(a_3_3_cek_encrypted)
    # A.3.4
    a_3_4_iv = [3,22,60,12,43,67,104,105,108,108,105,99,111,116,104,101].pack('C*')
    a_3_4_iv_b64 = "AxY8DCtDaGlsbGljb3RoZQ"
    assert_equal a_3_4_iv_b64, JOSE.urlsafe_encode64(a_3_4_iv)
    # A.3.5
    a_3_5_aad = [101,121,74,104,98,71,99,105,79,105,74,66,77,84,73,52,83,49,99,105,76,67,74,108,98,109,77,105,79,105,74,66,77,84,73,52,81,48,74,68,76,85,104,84,77,106,85,50,73,110,48].pack('C*')
    assert_equal a_3_5_aad, a_3_1_jwe_json_b64
    # A.3.6
    a_3_6_txt_cipher = [40,57,83,181,119,33,133,148,198,185,243,24,152,230,6,75,129,223,127,19,210,82,183,230,168,33,215,104,143,112,56,102].pack('C*')
    a_3_6_txt_tag = [83,73,191,98,104,205,211,128,201,189,199,133,32,38,194,85].pack('C*')
    a_3_6_txt_cipher_b64 = "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY"
    a_3_6_txt_tag_b64 = "U0m_YmjN04DJvceFICbCVQ"
    assert_equal a_3_6_txt_cipher_b64, JOSE.urlsafe_encode64(a_3_6_txt_cipher)
    assert_equal a_3_6_txt_tag_b64, JOSE.urlsafe_encode64(a_3_6_txt_tag)
    # A.3.7
    a_3_7_jwe_compact = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ.AxY8DCtDaGlsbGljb3RoZQ.KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.U0m_YmjN04DJvceFICbCVQ"
    a_3_7_txt, a_3_7_jwe = JOSE::JWE.block_decrypt(a_3_3_jwk, a_3_7_jwe_compact)
    assert_equal a_3_txt, a_3_7_txt
    assert_equal a_3_1_jwe, a_3_7_jwe
    # Roundtrip test
    a_3_7_map = JOSE::JWE.block_encrypt(a_3_3_jwk, a_3_txt, a_3_1_jwe, a_3_2_cek, a_3_4_iv)
    a_3_7_txt, a_3_7_jwe = JOSE::JWE.block_decrypt(a_3_3_jwk, a_3_7_map)
    assert_equal a_3_txt, a_3_7_txt
    assert_equal a_3_1_jwe, a_3_7_jwe
  end

  # JSON Web Signature (JWS)
  # Appendix A.1.  Example JWS Using HMAC SHA-256
  # https://tools.ietf.org/html/rfc7515#appendix-A.1
  def test_jws_a_1
    # A.1.1
    a_1_1_jws_json = "{\"typ\":\"JWT\",\r\n \"alg\":\"HS256\"}"
    a_1_1_jws_json_binary = [123,34,116,121,112,34,58,34,74,87,84,34,44,13,10,32,34,97,108,103,34,58,34,72,83,50,53,54,34,125].pack('C*')
    assert_equal a_1_1_jws_json, a_1_1_jws_json_binary
    a_1_1_jws_json_b64 = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"
    a_1_1_jws_map = JOSE.decode(a_1_1_jws_json)
    a_1_1_jws = JOSE::JWS.from_binary(a_1_1_jws_json)
    assert_equal a_1_1_jws_map, a_1_1_jws.to_map
    assert_equal a_1_1_jws_json_b64, JOSE.urlsafe_encode64(a_1_1_jws_json)
    a_1_1_payload = "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}"
    a_1_1_payload_binary = [123,34,105,115,115,34,58,34,106,111,101,34,44,13,10,32,34,101,120,112,34,58,49,51,48,48,56,49,57,51,56,48,44,13,10,32,34,104,116,116,112,58,47,47,101,120,97,109,112,108,101,46,99,111,109,47,105,115,95,114,111,111,116,34,58,116,114,117,101,125].pack('C*')
    assert_equal a_1_1_payload, a_1_1_payload_binary
    a_1_1_payload_b64 = "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
    assert_equal a_1_1_payload_b64, JOSE.urlsafe_encode64(a_1_1_payload)
    a_1_1_signing_input = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
    a_1_1_signing_input_binary = [101,121,74,48,101,88,65,105,79,105,74,75,86,49,81,105,76,65,48,75,73,67,74,104,98,71,99,105,79,105,74,73,85,122,73,49,78,105,74,57,46,101,121,74,112,99,51,77,105,79,105,74,113,98,50,85,105,76,65,48,75,73,67,74,108,101,72,65,105,79,106,69,122,77,68,65,52,77,84,107,122,79,68,65,115,68,81,111,103,73,109,104,48,100,72,65,54,76,121,57,108,101,71,70,116,99,71,120,108,76,109,78,118,98,83,57,112,99,49,57,121,98,50,57,48,73,106,112,48,99,110,86,108,102,81].pack('C*')
    assert_equal a_1_1_signing_input, a_1_1_signing_input_binary
    assert_equal a_1_1_signing_input, "#{a_1_1_jws_json_b64}.#{a_1_1_payload_b64}"
    a_1_1_jwk_json = "{\"kty\":\"oct\",\"k\":\"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow\"}"
    a_1_1_jwk = JOSE::JWK.from_binary(a_1_1_jwk_json)
    a_1_1_signature = [116,24,223,180,151,153,224,37,79,250,96,125,216,173,187,186,22,212,37,77,105,214,191,240,91,88,5,88,83,132,141,121].pack('C*')
    a_1_1_signature_b64 = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    assert_equal a_1_1_signature_b64, JOSE.urlsafe_encode64(a_1_1_signature)
    assert_equal a_1_1_signature_b64, JOSE.urlsafe_encode64(a_1_1_jws.alg.sign(a_1_1_jwk, a_1_1_signing_input))
    a_1_1_compact = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    assert_equal a_1_1_compact, "#{a_1_1_signing_input}.#{a_1_1_signature_b64}"
    # A.1.2
    verified, payload, jws = JOSE::JWS.verify(a_1_1_jwk, a_1_1_compact)
    assert verified
    assert_equal payload, a_1_1_payload
    assert_equal jws, a_1_1_jws
    # Sign and Verify
    signed = JOSE::JWS.sign(a_1_1_jwk, a_1_1_payload, a_1_1_jws).compact
    verified, payload, jws = JOSE::JWS.verify(a_1_1_jwk, signed)
    assert verified
    assert_equal payload, a_1_1_payload
    assert_equal jws, a_1_1_jws
  end

  # JSON Web Signature (JWS)
  # Appendix A.2.  Example JWS Using RSASSA-PKCS1-v1_5 SHA-256
  # https://tools.ietf.org/html/rfc7515#appendix-A.2
  def test_jws_a_2
    # A.2.1
    a_2_1_jws_json = "{\"alg\":\"RS256\"}"
    a_2_1_jws_json_binary = [123,34,97,108,103,34,58,34,82,83,50,53,54,34,125].pack('C*')
    assert_equal a_2_1_jws_json, a_2_1_jws_json_binary
    a_2_1_jws_json_b64 = "eyJhbGciOiJSUzI1NiJ9"
    a_2_1_jws_map = JOSE.decode(a_2_1_jws_json)
    a_2_1_jws = JOSE::JWS.from_binary(a_2_1_jws_json)
    assert_equal a_2_1_jws_map, a_2_1_jws.to_map
    assert_equal a_2_1_jws_json_b64, JOSE.urlsafe_encode64(a_2_1_jws_json)
    a_2_1_payload = "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}"
    a_2_1_payload_binary = [123,34,105,115,115,34,58,34,106,111,101,34,44,13,10,32,34,101,120,112,34,58,49,51,48,48,56,49,57,51,56,48,44,13,10,32,34,104,116,116,112,58,47,47,101,120,97,109,112,108,101,46,99,111,109,47,105,115,95,114,111,111,116,34,58,116,114,117,101,125].pack('C*')
    assert_equal a_2_1_payload, a_2_1_payload_binary
    a_2_1_payload_b64 = "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
    assert_equal a_2_1_payload_b64, JOSE.urlsafe_encode64(a_2_1_payload)
    a_2_1_signing_input = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
    a_2_1_signing_input_binary = [101,121,74,104,98,71,99,105,79,105,74,83,85,122,73,49,78,105,74,57,46,101,121,74,112,99,51,77,105,79,105,74,113,98,50,85,105,76,65,48,75,73,67,74,108,101,72,65,105,79,106,69,122,77,68,65,52,77,84,107,122,79,68,65,115,68,81,111,103,73,109,104,48,100,72,65,54,76,121,57,108,101,71,70,116,99,71,120,108,76,109,78,118,98,83,57,112,99,49,57,121,98,50,57,48,73,106,112,48,99,110,86,108,102,81].pack('C*')
    assert_equal a_2_1_signing_input, a_2_1_signing_input_binary
    assert_equal a_2_1_signing_input, "#{a_2_1_jws_json_b64}.#{a_2_1_payload_b64}"
    a_2_1_jwk_json = "{\"kty\":\"RSA\",\"n\":\"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ\",\"e\":\"AQAB\",\"d\":\"Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ\",\"p\":\"4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc\",\"q\":\"uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc\",\"dp\":\"BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3QCLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0\",\"dq\":\"h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-kyNlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU\",\"qi\":\"IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2oy26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLUW0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U\"}"
    a_2_1_jwk = JOSE::JWK.from_binary(a_2_1_jwk_json)
    a_2_1_signature = [112,46,33,137,67,232,143,209,30,181,216,45,191,120,69,243,65,6,174,27,129,255,247,115,17,22,173,209,113,125,131,101,109,66,10,253,60,150,238,221,115,162,102,62,81,102,104,123,0,11,135,34,110,1,135,237,16,115,249,69,229,130,173,252,239,22,216,90,121,142,232,198,109,219,61,184,151,91,23,208,148,2,190,237,213,217,217,112,7,16,141,178,129,96,213,248,4,12,167,68,87,98,184,31,190,127,249,217,46,10,231,111,36,242,91,51,187,230,244,74,230,30,177,4,10,203,32,4,77,62,249,18,142,212,1,48,121,91,212,189,59,65,238,202,208,102,171,101,25,129,253,228,141,247,127,55,45,195,139,159,175,221,59,239,177,139,93,163,204,60,46,176,47,158,58,65,214,18,202,173,21,145,18,115,160,95,35,185,232,56,250,175,132,157,105,132,41,239,90,30,136,121,130,54,195,212,14,96,69,34,165,68,200,242,122,122,45,184,6,99,209,108,247,202,234,86,222,64,92,178,33,90,69,178,194,85,102,181,90,193,167,72,160,112,223,200,163,42,70,149,67,208,25,238,251,71].pack('C*')
    a_2_1_signature_b64 = "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw"
    assert_equal a_2_1_signature_b64, JOSE.urlsafe_encode64(a_2_1_signature)
    assert_equal a_2_1_signature_b64, JOSE.urlsafe_encode64(a_2_1_jws.alg.sign(a_2_1_jwk, a_2_1_signing_input))
    a_2_1_compact = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw"
    assert_equal a_2_1_compact, "#{a_2_1_signing_input}.#{a_2_1_signature_b64}"
    # A.2.2
    verified, payload, jws = JOSE::JWS.verify(a_2_1_jwk, a_2_1_compact)
    assert verified
    assert_equal payload, a_2_1_payload
    assert_equal jws, a_2_1_jws
    # Sign and Verify
    signed = JOSE::JWS.sign(a_2_1_jwk, a_2_1_payload, a_2_1_jws).compact
    verified, payload, jws = JOSE::JWS.verify(a_2_1_jwk, signed)
    assert verified
    assert_equal payload, a_2_1_payload
    assert_equal jws, a_2_1_jws
  end

  # JSON Web Signature (JWS)
  # Appendix A.3.  Example JWS Using ECDSA P-256 SHA-256
  # https://tools.ietf.org/html/rfc7515#appendix-A.3
  def test_jws_a_3
    # A.3.1
    a_3_1_jws_json = "{\"alg\":\"ES256\"}"
    a_3_1_jws_json_binary = [123,34,97,108,103,34,58,34,69,83,50,53,54,34,125].pack('C*')
    assert_equal a_3_1_jws_json, a_3_1_jws_json_binary
    a_3_1_jws_json_b64 = "eyJhbGciOiJFUzI1NiJ9"
    a_3_1_jws_map = JOSE.decode(a_3_1_jws_json)
    a_3_1_jws = JOSE::JWS.from_binary(a_3_1_jws_json)
    assert_equal a_3_1_jws_map, a_3_1_jws.to_map
    assert_equal a_3_1_jws_json_b64, JOSE.urlsafe_encode64(a_3_1_jws_json)
    a_3_1_payload = "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}"
    a_3_1_payload_binary = [123,34,105,115,115,34,58,34,106,111,101,34,44,13,10,32,34,101,120,112,34,58,49,51,48,48,56,49,57,51,56,48,44,13,10,32,34,104,116,116,112,58,47,47,101,120,97,109,112,108,101,46,99,111,109,47,105,115,95,114,111,111,116,34,58,116,114,117,101,125].pack('C*')
    assert_equal a_3_1_payload, a_3_1_payload_binary
    a_3_1_payload_b64 = "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
    assert_equal a_3_1_payload_b64, JOSE.urlsafe_encode64(a_3_1_payload)
    a_3_1_signing_input = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
    a_3_1_signing_input_binary = [101,121,74,104,98,71,99,105,79,105,74,70,85,122,73,49,78,105,74,57,46,101,121,74,112,99,51,77,105,79,105,74,113,98,50,85,105,76,65,48,75,73,67,74,108,101,72,65,105,79,106,69,122,77,68,65,52,77,84,107,122,79,68,65,115,68,81,111,103,73,109,104,48,100,72,65,54,76,121,57,108,101,71,70,116,99,71,120,108,76,109,78,118,98,83,57,112,99,49,57,121,98,50,57,48,73,106,112,48,99,110,86,108,102,81].pack('C*')
    assert_equal a_3_1_signing_input, a_3_1_signing_input_binary
    assert_equal a_3_1_signing_input, "#{a_3_1_jws_json_b64}.#{a_3_1_payload_b64}"
    a_3_1_jwk_json = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\",\"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\",\"d\":\"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI\"}"
    a_3_1_jwk = JOSE::JWK.from_binary(a_3_1_jwk_json)
    a_3_1_signature = [14,209,33,83,121,99,108,72,60,47,127,21,88,7,212,2,163,178,40,3,58,249,124,126,23,129,154,195,22,158,166,101,197,10,7,211,140,60,112,229,216,241,45,175,8,74,84,128,166,101,144,197,242,147,80,154,143,63,127,138,131,163,84,213].pack('C*')
    a_3_1_signature_b64 = "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"
    assert_equal a_3_1_signature_b64, JOSE.urlsafe_encode64(a_3_1_signature)
    # ECDSA produces a different signature value each signing.
    refute_equal a_3_1_signature_b64, JOSE.urlsafe_encode64(a_3_1_jws.alg.sign(a_3_1_jwk, a_3_1_signing_input))
    a_3_1_compact = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"
    assert_equal a_3_1_compact, "#{a_3_1_signing_input}.#{a_3_1_signature_b64}"
    # A.3.2
    verified, payload, jws = JOSE::JWS.verify(a_3_1_jwk, a_3_1_compact)
    assert verified
    assert_equal payload, a_3_1_payload
    assert_equal jws, a_3_1_jws
    # Sign and Verify
    signed = JOSE::JWS.sign(a_3_1_jwk, a_3_1_payload, a_3_1_jws).compact
    verified, payload, jws = JOSE::JWS.verify(a_3_1_jwk, signed)
    assert verified
    assert_equal payload, a_3_1_payload
    assert_equal jws, a_3_1_jws
  end

  # JSON Web Signature (JWS)
  # Appendix A.4.  Example JWS Using ECDSA P-521 SHA-512
  # https://tools.ietf.org/html/rfc7515#appendix-A.4
  def test_jws_a_4
    # A.4.1
    a_4_1_jws_json = "{\"alg\":\"ES512\"}"
    a_4_1_jws_json_binary = [123,34,97,108,103,34,58,34,69,83,53,49,50,34,125].pack('C*')
    assert_equal a_4_1_jws_json, a_4_1_jws_json_binary
    a_4_1_jws_json_b64 = "eyJhbGciOiJFUzUxMiJ9"
    a_4_1_jws_map = JOSE.decode(a_4_1_jws_json)
    a_4_1_jws = JOSE::JWS.from_binary(a_4_1_jws_json)
    assert_equal a_4_1_jws_map, a_4_1_jws.to_map
    assert_equal a_4_1_jws_json_b64, JOSE.urlsafe_encode64(a_4_1_jws_json)
    a_4_1_payload = "Payload"
    a_4_1_payload_binary = [80,97,121,108,111,97,100].pack('C*')
    assert_equal a_4_1_payload, a_4_1_payload_binary
    a_4_1_payload_b64 = "UGF5bG9hZA"
    assert_equal a_4_1_payload_b64, JOSE.urlsafe_encode64(a_4_1_payload)
    a_4_1_signing_input = "eyJhbGciOiJFUzUxMiJ9.UGF5bG9hZA"
    a_4_1_signing_input_binary = [101,121,74,104,98,71,99,105,79,105,74,70,85,122,85,120,77,105,74,57,46,85,71,70,53,98,71,57,104,90,65].pack('C*')
    assert_equal a_4_1_signing_input, a_4_1_signing_input_binary
    assert_equal a_4_1_signing_input, "#{a_4_1_jws_json_b64}.#{a_4_1_payload_b64}"
    a_4_1_jwk_json = "{\"kty\":\"EC\",\"crv\":\"P-521\",\"x\":\"AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk\",\"y\":\"ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2\",\"d\":\"AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPAxerEzgdRhajnu0ferB0d53vM9mE15j2C\"}"
    a_4_1_jwk = JOSE::JWK.from_binary(a_4_1_jwk_json)
    a_4_1_signature = [1,220,12,129,231,171,194,209,232,135,233,117,247,105,122,210,26,125,192,1,217,21,82,91,45,240,255,83,19,34,239,71,48,157,147,152,105,18,53,108,163,214,68,231,62,153,150,106,194,164,246,72,143,138,24,50,129,223,133,206,209,172,63,237,119,109,0,111,6,105,44,5,41,208,128,61,152,40,92,61,152,4,150,66,60,69,247,196,170,81,193,199,78,59,194,169,16,124,9,143,42,142,131,48,206,238,34,175,83,203,220,159,3,107,155,22,27,73,111,68,68,21,238,144,229,232,148,188,222,59,242,103].pack('C*')
    a_4_1_signature_b64 = "AdwMgeerwtHoh-l192l60hp9wAHZFVJbLfD_UxMi70cwnZOYaRI1bKPWROc-mZZqwqT2SI-KGDKB34XO0aw_7XdtAG8GaSwFKdCAPZgoXD2YBJZCPEX3xKpRwcdOO8KpEHwJjyqOgzDO7iKvU8vcnwNrmxYbSW9ERBXukOXolLzeO_Jn"
    assert_equal a_4_1_signature_b64, JOSE.urlsafe_encode64(a_4_1_signature)
    # ECDSA produces a different signature value each signing.
    refute_equal a_4_1_signature_b64, JOSE.urlsafe_encode64(a_4_1_jws.alg.sign(a_4_1_jwk, a_4_1_signing_input))
    a_4_1_compact = "eyJhbGciOiJFUzUxMiJ9.UGF5bG9hZA.AdwMgeerwtHoh-l192l60hp9wAHZFVJbLfD_UxMi70cwnZOYaRI1bKPWROc-mZZqwqT2SI-KGDKB34XO0aw_7XdtAG8GaSwFKdCAPZgoXD2YBJZCPEX3xKpRwcdOO8KpEHwJjyqOgzDO7iKvU8vcnwNrmxYbSW9ERBXukOXolLzeO_Jn"
    assert_equal a_4_1_compact, "#{a_4_1_signing_input}.#{a_4_1_signature_b64}"
    # A.4.2
    verified, payload, jws = JOSE::JWS.verify(a_4_1_jwk, a_4_1_compact)
    assert verified
    assert_equal payload, a_4_1_payload
    assert_equal jws, a_4_1_jws
    # Sign and Verify
    signed = JOSE::JWS.sign(a_4_1_jwk, a_4_1_payload, a_4_1_jws).compact
    verified, payload, jws = JOSE::JWS.verify(a_4_1_jwk, signed)
    assert verified
    assert_equal payload, a_4_1_payload
    assert_equal jws, a_4_1_jws
  end

  # JSON Web Signature (JWS)
  # Appendix A.5.  Example Unsecured JWS
  # https://tools.ietf.org/html/rfc7515#appendix-A.5
  def test_jws_a_5
    # A.5.1
    a_5_1_jws_json = "{\"alg\":\"none\"}"
    a_5_1_jws_json_b64 = "eyJhbGciOiJub25lIn0"
    a_5_1_jws_map = JOSE.decode(a_5_1_jws_json)
    a_5_1_jws = JOSE::JWS.from_binary(a_5_1_jws_json)
    assert_equal a_5_1_jws_map, a_5_1_jws.to_map
    assert_equal a_5_1_jws_json_b64, JOSE.urlsafe_encode64(a_5_1_jws_json)
    a_5_1_payload = "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}"
    a_5_1_payload_binary = [123,34,105,115,115,34,58,34,106,111,101,34,44,13,10,32,34,101,120,112,34,58,49,51,48,48,56,49,57,51,56,48,44,13,10,32,34,104,116,116,112,58,47,47,101,120,97,109,112,108,101,46,99,111,109,47,105,115,95,114,111,111,116,34,58,116,114,117,101,125].pack('C*')
    assert_equal a_5_1_payload, a_5_1_payload_binary
    a_5_1_payload_b64 = "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
    assert_equal a_5_1_payload_b64, JOSE.urlsafe_encode64(a_5_1_payload)
    a_5_1_signing_input = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
    assert_equal a_5_1_signing_input, "#{a_5_1_jws_json_b64}.#{a_5_1_payload_b64}"
    a_5_1_jwk_json = "{\"k\":\"\",\"kty\":\"oct\"}"
    a_5_1_jwk = JOSE::JWK.from_binary(a_5_1_jwk_json)
    a_5_1_signature = [].pack('C*')
    a_5_1_signature_b64 = ""
    assert_equal a_5_1_signature_b64, JOSE.urlsafe_encode64(a_5_1_signature)
    unsecured_signing = JOSE.unsecured_signing
    begin
      JOSE.unsecured_signing = false
      assert_raises(NotImplementedError) { JOSE.urlsafe_encode64(a_5_1_jws.alg.sign(a_5_1_jwk, a_5_1_signing_input)) }
      JOSE.unsecured_signing = true
      assert_equal a_5_1_signature_b64, JOSE.urlsafe_encode64(a_5_1_jws.alg.sign(a_5_1_jwk, a_5_1_signing_input))
      a_5_1_compact = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ."
      assert_equal a_5_1_compact, "#{a_5_1_signing_input}.#{a_5_1_signature_b64}"
      # A.5.2
      JOSE.unsecured_signing = false
      assert_raises(NotImplementedError) { JOSE::JWS.verify(a_5_1_jwk, a_5_1_compact) }
      JOSE.unsecured_signing = true
      verified, payload, jws = JOSE::JWS.verify(a_5_1_jwk, a_5_1_compact)
      assert verified
      assert_equal payload, a_5_1_payload
      assert_equal jws, a_5_1_jws
      # Sign and Verify
      signed = JOSE::JWS.sign(a_5_1_jwk, a_5_1_payload, a_5_1_jws).compact
      verified, payload, jws = JOSE::JWS.verify(a_5_1_jwk, signed)
      assert verified
      assert_equal payload, a_5_1_payload
      assert_equal jws, a_5_1_jws
    ensure
      JOSE.unsecured_signing = unsecured_signing
    end
  end

  def test_property_of_encode_and_decode
    property_of {
      urlsafe_base64_dict
    }.check { |term|
      binary = JOSE.encode(term)
      if first_sorted_key = term.keys.sort[0]
        assert binary.start_with?("{\"#{first_sorted_key}\":")
      end
      roundtrip = JOSE.decode(binary)
      assert_equal roundtrip, term
    }
  end

  def test_rfc7520_5_9
    figures = {
      72  => [89,111,117,32,99,97,110,32,116,114,117,115,116,32,117,115,32,116,111,32,115,116,105,99,107,32,119,105,116,104,32,121,111,117,32,116,104,114,111,117,103,104,32,116,104,105,99,107,32,97,110,100,32,116,104,105,110,226,128,147,116,111,32,116,104,101,32,98,105,116,116,101,114,32,101,110,100,46,32,65,110,100,32,121,111,117,32,99,97,110,32,116,114,117,115,116,32,117,115,32,116,111,32,107,101,101,112,32,97,110,121,32,115,101,99,114,101,116,32,111,102,32,121,111,117,114,115,226,128,147,99,108,111,115,101,114,32,116,104,97,110,32,121,111,117,32,107,101,101,112,32,105,116,32,121,111,117,114,115,101,108,102,46,32,66,117,116,32,121,111,117,32,99,97,110,110,111,116,32,116,114,117,115,116,32,117,115,32,116,111,32,108,101,116,32,121,111,117,32,102,97,99,101,32,116,114,111,117,98,108,101,32,97,108,111,110,101,44,32,97,110,100,32,103,111,32,111,102,102,32,119,105,116,104,111,117,116,32,97,32,119,111,114,100,46,32,87,101,32,97,114,101,32,121,111,117,114,32,102,114,105,101,110,100,115,44,32,70,114,111,100,111,46].pack('C*'),
      151 => '{"kty":"oct","kid":"81b20965-8332-43d9-a468-82160ad91ac8","use":"enc","alg":"A128KW","k":"GZy6sIZ6wl9NJOKB-jnmVQ"}',
      162 => 'bY_BDcIwDEVX-QNU3QEOrIA4pqlDokYxchxVvbEDGzIJbioOSJwc-f___HPjBu8KVFpVtAplVE1-wZo0YjNZo3C7R5v72pV5f5X382VWjYQpqZKAyjziZOr2B7kQPSy6oZIXUnDYbVKN4jNXi2u0yB7t1qSHTjmMODf9QgvrDzfTIQXnyQRuUya4zIWG3vTOdir0v7BRHFYWq3k1k1A_gSDJqtcBF-GZxw8',
      163 => 'hC-MpLZSuwWv8sexS6ydfw',
      164 => 'p9pUq6XHY0jfEZIl',
      165 => '5vUT2WOtQxKWcekM_IzVQwkGgzlFDwPi',
      166 => '{"alg":"A128KW","kid":"81b20965-8332-43d9-a468-82160ad91ac8","enc":"A128GCM","zip":"DEF"}',
      167 => 'eyJhbGciOiJBMTI4S1ciLCJraWQiOiI4MWIyMDk2NS04MzMyLTQzZDktYTQ2OC04MjE2MGFkOTFhYzgiLCJlbmMiOiJBMTI4R0NNIiwiemlwIjoiREVGIn0',
      168 => 'HbDtOsdai1oYziSx25KEeTxmwnh8L8jKMFNc1k3zmMI6VB8hry57tDZ61jXyezSPt0fdLVfe6Jf5y5-JaCap_JQBcb5opbmT60uWGml8blyiMQmOn9J--XhhlYg0m-BHaqfDO5iTOWxPxFMUedx7WCy8mxgDHj0aBMG6152PsM-w5E_o2B3jDbrYBKhpYA7qi3AyijnCJ7BP9rr3U8kxExCpG3mK420TjOw',
      169 => 'VILuUwuIxaLVmh5X-T7kmA',
      170 => 'eyJhbGciOiJBMTI4S1ciLCJraWQiOiI4MWIyMDk2NS04MzMyLTQzZDktYTQ2OC04MjE2MGFkOTFhYzgiLCJlbmMiOiJBMTI4R0NNIiwiemlwIjoiREVGIn0.5vUT2WOtQxKWcekM_IzVQwkGgzlFDwPi.p9pUq6XHY0jfEZIl.HbDtOsdai1oYziSx25KEeTxmwnh8L8jKMFNc1k3zmMI6VB8hry57tDZ61jXyezSPt0fdLVfe6Jf5y5-JaCap_JQBcb5opbmT60uWGml8blyiMQmOn9J--XhhlYg0m-BHaqfDO5iTOWxPxFMUedx7WCy8mxgDHj0aBMG6152PsM-w5E_o2B3jDbrYBKhpYA7qi3AyijnCJ7BP9rr3U8kxExCpG3mK420TjOw.VILuUwuIxaLVmh5X-T7kmA',
      172 => '{"protected":"eyJhbGciOiJBMTI4S1ciLCJraWQiOiI4MWIyMDk2NS04MzMyLTQzZDktYTQ2OC04MjE2MGFkOTFhYzgiLCJlbmMiOiJBMTI4R0NNIiwiemlwIjoiREVGIn0","encrypted_key":"5vUT2WOtQxKWcekM_IzVQwkGgzlFDwPi","iv":"p9pUq6XHY0jfEZIl","ciphertext":"HbDtOsdai1oYziSx25KEeTxmwnh8L8jKMFNc1k3zmMI6VB8hry57tDZ61jXyezSPt0fdLVfe6Jf5y5-JaCap_JQBcb5opbmT60uWGml8blyiMQmOn9J--XhhlYg0m-BHaqfDO5iTOWxPxFMUedx7WCy8mxgDHj0aBMG6152PsM-w5E_o2B3jDbrYBKhpYA7qi3AyijnCJ7BP9rr3U8kxExCpG3mK420TjOw","tag":"VILuUwuIxaLVmh5X-T7kmA"}'
    }
    # 5.9.1
    v_5_9_1_plain_text = figures[72]
    v_5_9_1_jwk = JOSE::JWK.from_binary(figures[151])
    # 5.9.2
    v_5_9_2_compressed_plain_text = figures[162]
    assert_equal v_5_9_1_plain_text, JOSE::JWE::ZIP_DEF.new.uncompress(JOSE.urlsafe_decode64(v_5_9_2_compressed_plain_text))
    assert_equal v_5_9_2_compressed_plain_text, JOSE.urlsafe_encode64(JOSE::JWE::ZIP_DEF.new.compress(v_5_9_1_plain_text))
    v_5_9_2_cek = figures[163]
    v_5_9_2_iv = figures[164]
    # 5.9.3
    v_5_9_3_encrypted_key = figures[165]
    assert_equal v_5_9_3_encrypted_key, JOSE.urlsafe_encode64(JOSE::JWE::ALG_AES_KW.new(128).key_encrypt(v_5_9_1_jwk, nil, JOSE.urlsafe_decode64(v_5_9_2_cek)).first)
    assert_equal v_5_9_2_cek, JOSE.urlsafe_encode64(JOSE::JWE::ALG_AES_KW.new(128).key_decrypt(v_5_9_1_jwk, nil, JOSE.urlsafe_decode64(v_5_9_3_encrypted_key)))
    # 5.9.4
    v_5_9_4_jwe = JOSE::JWE.from_binary(figures[166])
    # commenting out unused variables because they are helpful as documentation
    # v_5_9_4_jwe_protected = figures[167]
    # v_5_9_4_cipher_text = figures[168]
    # v_5_9_4_cipher_tag = figures[169]
    v_5_9_5_jwe_compact = figures[170]
    v_5_9_5_jwe_map = JOSE.decode(figures[172])
    plain_text, jwe = JOSE::JWE.block_decrypt(v_5_9_1_jwk, v_5_9_5_jwe_compact)
    assert_equal v_5_9_1_plain_text, plain_text
    assert_equal v_5_9_4_jwe, jwe
    plain_text, jwe = JOSE::JWE.block_decrypt(v_5_9_1_jwk, v_5_9_5_jwe_map)
    assert_equal v_5_9_1_plain_text, plain_text
    assert_equal v_5_9_4_jwe, jwe
    # Roundtrip test
    cipher_text = JOSE::JWE.block_encrypt(v_5_9_1_jwk, v_5_9_1_plain_text, v_5_9_4_jwe, JOSE.urlsafe_decode64(v_5_9_2_cek), JOSE.urlsafe_decode64(v_5_9_2_iv)).compact
    plain_text, _ = JOSE::JWE.block_decrypt(v_5_9_1_jwk, cipher_text)
    assert_equal v_5_9_1_plain_text, plain_text
  end
end
