require 'test_helper'

class CFRGCurvesTest < Minitest::Test

  def test_curve25519_eddsa_ed25519
    vectors = [
      [ # TEST 1
        hexstr2bin(
          "9d61b19deffd5a60ba844af492ec2cc4"\
          "4449c5697b326919703bac031cae7f60"), # SECRET KEY
        hexstr2bin(
          "d75a980182b10ab7d54bfed3c964073a"\
          "0ee172f3daa62325af021a68f707511a"), # PUBLIC KEY
        "", # MESSAGE
        hexstr2bin(
          "e5564300c360ac729086e2cc806e828a"\
          "84877f1eb8e5d974d873e06522490155"\
          "5fb8821590a33bacc61e39701cf9b46b"\
          "d25bf5f0595bbe24655141438e7a100b") # SIGNATURE
      ],
      [ # TEST 2
        hexstr2bin(
          "4ccd089b28ff96da9db6c346ec114e0f"\
          "5b8a319f35aba624da8cf6ed4fb8a6fb"), # SECRET KEY
        hexstr2bin(
          "3d4017c3e843895a92b70aa74d1b7ebc"\
          "9c982ccf2ec4968cc0cd55f12af4660c"), # PUBLIC KEY
        hexstr2bin("72"), # MESSAGE
        hexstr2bin(
          "92a009a9f0d4cab8720e820b5f642540"\
          "a2b27b5416503f8fb3762223ebdb69da"\
          "085ac1e43e15996e458f3613d0f11d8c"\
          "387b2eaeb4302aeeb00d291612bb0c00") # SIGNATURE
      ],
      [ # TEST 3
        hexstr2bin(
          "c5aa8df43f9f837bedb7442f31dcb7b1"\
          "66d38535076f094b85ce3a2e0b4458f7"), # SECRET KEY
        hexstr2bin(
          "fc51cd8e6218a1a38da47ed00230f058"\
          "0816ed13ba3303ac5deb911548908025"), # PUBLIC KEY
        hexstr2bin("af82"), # MESSAGE
        hexstr2bin(
          "6291d657deec24024827e69c3abe01a3"\
          "0ce548a284743a445e3680d7db5ac3ac"\
          "18ff9b538d16f290ae67f760984dc659"\
          "4a7c15e9716ed28dc027beceea1ec40a") # SIGNATURE
      ],
      [ # TEST 1024
        hexstr2bin(
          "f5e5767cf153319517630f226876b86c"\
          "8160cc583bc013744c6bf255f5cc0ee5"), # SECRET KEY
        hexstr2bin(
          "278117fc144c72340f67d0f2316e8386"\
          "ceffbf2b2428c9c51fef7c597f1d426e"), # PUBLIC KEY
        hexstr2bin(
          "08b8b2b733424243760fe426a4b54908"\
          "632110a66c2f6591eabd3345e3e4eb98"\
          "fa6e264bf09efe12ee50f8f54e9f77b1"\
          "e355f6c50544e23fb1433ddf73be84d8"\
          "79de7c0046dc4996d9e773f4bc9efe57"\
          "38829adb26c81b37c93a1b270b20329d"\
          "658675fc6ea534e0810a4432826bf58c"\
          "941efb65d57a338bbd2e26640f89ffbc"\
          "1a858efcb8550ee3a5e1998bd177e93a"\
          "7363c344fe6b199ee5d02e82d522c4fe"\
          "ba15452f80288a821a579116ec6dad2b"\
          "3b310da903401aa62100ab5d1a36553e"\
          "06203b33890cc9b832f79ef80560ccb9"\
          "a39ce767967ed628c6ad573cb116dbef"\
          "efd75499da96bd68a8a97b928a8bbc10"\
          "3b6621fcde2beca1231d206be6cd9ec7"\
          "aff6f6c94fcd7204ed3455c68c83f4a4"\
          "1da4af2b74ef5c53f1d8ac70bdcb7ed1"\
          "85ce81bd84359d44254d95629e9855a9"\
          "4a7c1958d1f8ada5d0532ed8a5aa3fb2"\
          "d17ba70eb6248e594e1a2297acbbb39d"\
          "502f1a8c6eb6f1ce22b3de1a1f40cc24"\
          "554119a831a9aad6079cad88425de6bd"\
          "e1a9187ebb6092cf67bf2b13fd65f270"\
          "88d78b7e883c8759d2c4f5c65adb7553"\
          "878ad575f9fad878e80a0c9ba63bcbcc"\
          "2732e69485bbc9c90bfbd62481d9089b"\
          "eccf80cfe2df16a2cf65bd92dd597b07"\
          "07e0917af48bbb75fed413d238f5555a"\
          "7a569d80c3414a8d0859dc65a46128ba"\
          "b27af87a71314f318c782b23ebfe808b"\
          "82b0ce26401d2e22f04d83d1255dc51a"\
          "ddd3b75a2b1ae0784504df543af8969b"\
          "e3ea7082ff7fc9888c144da2af58429e"\
          "c96031dbcad3dad9af0dcbaaaf268cb8"\
          "fcffead94f3c7ca495e056a9b47acdb7"\
          "51fb73e666c6c655ade8297297d07ad1"\
          "ba5e43f1bca32301651339e22904cc8c"\
          "42f58c30c04aafdb038dda0847dd988d"\
          "cda6f3bfd15c4b4c4525004aa06eeff8"\
          "ca61783aacec57fb3d1f92b0fe2fd1a8"\
          "5f6724517b65e614ad6808d6f6ee34df"\
          "f7310fdc82aebfd904b01e1dc54b2927"\
          "094b2db68d6f903b68401adebf5a7e08"\
          "d78ff4ef5d63653a65040cf9bfd4aca7"\
          "984a74d37145986780fc0b16ac451649"\
          "de6188a7dbdf191f64b5fc5e2ab47b57"\
          "f7f7276cd419c17a3ca8e1b939ae49e4"\
          "88acba6b965610b5480109c8b17b80e1"\
          "b7b750dfc7598d5d5011fd2dcc5600a3"\
          "2ef5b52a1ecc820e308aa342721aac09"\
          "43bf6686b64b2579376504ccc493d97e"\
          "6aed3fb0f9cd71a43dd497f01f17c0e2"\
          "cb3797aa2a2f256656168e6c496afc5f"\
          "b93246f6b1116398a346f1a641f3b041"\
          "e989f7914f90cc2c7fff357876e506b5"\
          "0d334ba77c225bc307ba537152f3f161"\
          "0e4eafe595f6d9d90d11faa933a15ef1"\
          "369546868a7f3a45a96768d40fd9d034"\
          "12c091c6315cf4fde7cb68606937380d"\
          "b2eaaa707b4c4185c32eddcdd306705e"\
          "4dc1ffc872eeee475a64dfac86aba41c"\
          "0618983f8741c5ef68d3a101e8a3b8ca"\
          "c60c905c15fc910840b94c00a0b9d0"), # MESSAGE
        hexstr2bin(
          "0aab4c900501b3e24d7cdf4663326a3a"\
          "87df5e4843b2cbdb67cbf6e460fec350"\
          "aa5371b1508f9f4528ecea23c436d94b"\
          "5e8fcd4f681e30a6ac00a9704a188a03") # SIGNATURE
      ],
      [ # TEST SHA(abc)
        hexstr2bin(
          "833fe62409237b9d62ec77587520911e"\
          "9a759cec1d19755b7da901b96dca3d42"), # SECRET KEY
        hexstr2bin(
          "ec172b93ad5e563bf4932c70e1245034"\
          "c35467ef2efd4d64ebf819683467e2bf"), # PUBLIC KEY
        hexstr2bin(
          "ddaf35a193617abacc417349ae204131"\
          "12e6fa4e89a97ea20a9eeee64b55d39a"\
          "2192992a274fc1a836ba3c23a3feebbd"\
          "454d4423643ce80e2a9ac94fa54ca49f"), # MESSAGE
        hexstr2bin(
          "dc2a4459e7369633a52b1bf277839a00"\
          "201009a3efbf3ecb69bea2186c26b589"\
          "09351fc9ac90b3ecfdfbc7c66431e030"\
          "3dca179c138ac17ad9bef1177331a704") # SIGNATURE
      ]
    ]
    vectors.each do |(secret, pk, m, sig)|
      _pk, sk = JOSE::JWA::Ed25519.keypair(secret)
      assert_equal pk, _pk
      _sig = JOSE::JWA::Ed25519.sign(m, sk)
      assert_equal sig, _sig
      assert JOSE::JWA::Ed25519.verify(sig, m, pk)
      if JOSE::JWA::Curve25519_RbNaCl.__supported__?
        _pk, sk = JOSE::JWA::Ed25519_RbNaCl.keypair(secret)
        assert_equal pk, _pk
        _sig = JOSE::JWA::Ed25519_RbNaCl.sign(m, sk)
        assert_equal sig, _sig
        assert JOSE::JWA::Ed25519_RbNaCl.verify(sig, m, pk)
      end
    end
  end

  def test_curve25519_eddsa_ed25519ph
    vectors = [
      [ # TEST abc
        hexstr2bin(
          "833fe62409237b9d62ec77587520911e"\
          "9a759cec1d19755b7da901b96dca3d42"), # SECRET KEY
        hexstr2bin(
          "ec172b93ad5e563bf4932c70e1245034"\
          "c35467ef2efd4d64ebf819683467e2bf"), # PUBLIC KEY
        hexstr2bin("616263"), # MESSAGE
        hexstr2bin(
          "dc2a4459e7369633a52b1bf277839a00"\
          "201009a3efbf3ecb69bea2186c26b589"\
          "09351fc9ac90b3ecfdfbc7c66431e030"\
          "3dca179c138ac17ad9bef1177331a704") # SIGNATURE
      ]
    ]
    vectors.each do |(secret, pk, m, sig)|
      if JOSE::JWA::Curve25519_RbNaCl.__supported__?
        _pk, sk = JOSE::JWA::Ed25519_RbNaCl.keypair(secret)
        assert_equal pk, _pk
        _sig = JOSE::JWA::Ed25519_RbNaCl.sign_ph(m, sk)
        assert_equal sig, _sig
        assert JOSE::JWA::Ed25519_RbNaCl.verify_ph(sig, m, pk)
      end
    end
  end

  def test_curve25519_rfc7748_curve25519
    vectors = [
      [
        31029842492115040904895560451863089656472772604678260265531221036453811406496,  # Input scalar
        34426434033919594451155107781188821651316167215306631574996226621102155684838,  # Input u-coordinate
        hexstr2lint("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552") # Output u-coordinate
      ],
      [
        35156891815674817266734212754503633747128614016119564763269015315466259359304,  # Input scalar
        8883857351183929894090759386610649319417338800022198945255395922347792736741,   # Input u-coordinate
        hexstr2lint("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957") # Output u-coordinate
      ]
    ]
    vectors.each do |(input_scalar, input_u_coordinate, output_u_coordinate)|
      input_scalar        = JOSE::JWA::X25519.coerce_scalar_fe!(input_scalar)
      input_u_coordinate  = JOSE::JWA::X25519.coerce_coordinate_fe!(input_u_coordinate)
      output_u_coordinate = JOSE::JWA::X25519.coerce_coordinate_fe!(output_u_coordinate)
      assert_equal output_u_coordinate, JOSE::JWA::X25519.curve25519(input_scalar, input_u_coordinate)
      if JOSE::JWA::Curve25519_RbNaCl.__supported__?
        assert_equal output_u_coordinate.to_bytes(256), JOSE::JWA::X25519_RbNaCl.curve25519(input_scalar, input_u_coordinate)
      end
    end
  end

  def test_curve25519_rfc7748_x25519
    vectors = [
      [
        hexstr2bin("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"), # Alice's private key, f
        hexstr2bin("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"), # Alice's public key, X25519(f, 9)
        hexstr2bin("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"), # Bob's private key, g
        hexstr2bin("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"), # Bob's public key, X25519(g, 9)
        hexstr2bin("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")  # Their shared secret, K
      ]
    ]
    vectors.each do |(alice_sk, alice_pk, bob_sk, bob_pk, k)|
      assert_equal k, JOSE::JWA::X25519.shared_secret(alice_pk, bob_sk)
      assert_equal k, JOSE::JWA::X25519.shared_secret(bob_pk, alice_sk)
      if JOSE::JWA::Curve25519_RbNaCl.__supported__?
        assert_equal k, JOSE::JWA::X25519_RbNaCl.shared_secret(alice_pk, bob_sk)
        assert_equal k, JOSE::JWA::X25519_RbNaCl.shared_secret(bob_pk, alice_sk)
      end
    end
  end

  def test_curve448_eddsa_ed448
    vectors = [
      [ # Blank
        hexstr2bin(
          "6c82a562cb808d10d632be89c8513ebf"\
          "6c929f34ddfa8c9f63c9960ef6e348a3"\
          "528c8a3fcc2f044e39a3fc5b94492f8f"\
          "032e7549a20098f95b"), # SECRET KEY
        hexstr2bin(
          "5fd7449b59b461fd2ce787ec616ad46a"\
          "1da1342485a70e1f8a0ea75d80e96778"\
          "edf124769b46c7061bd6783df1e50f6c"\
          "d1fa1abeafe8256180"), # PUBLIC KEY
        "", # MESSAGE
        hexstr2bin(
          "533a37f6bbe457251f023c0d88f976ae"\
          "2dfb504a843e34d2074fd823d41a591f"\
          "2b233f034f628281f2fd7a22ddd47d78"\
          "28c59bd0a21bfd3980ff0d2028d4b18a"\
          "9df63e006c5d1c2d345b925d8dc00b41"\
          "04852db99ac5c7cdda8530a113a0f4db"\
          "b61149f05a7363268c71d95808ff2e65"\
          "2600") # SIGNATURE
      ],
      [ # 1 octet
        hexstr2bin(
          "c4eab05d357007c632f3dbb48489924d"\
          "552b08fe0c353a0d4a1f00acda2c463a"\
          "fbea67c5e8d2877c5e3bc397a659949e"\
          "f8021e954e0a12274e"), # SECRET KEY
        hexstr2bin(
          "43ba28f430cdff456ae531545f7ecd0a"\
          "c834a55d9358c0372bfa0c6c6798c086"\
          "6aea01eb00742802b8438ea4cb82169c"\
          "235160627b4c3a9480"), # PUBLIC KEY
        hexstr2bin("03"), # MESSAGE
        hexstr2bin(
          "26b8f91727bd62897af15e41eb43c377"\
          "efb9c610d48f2335cb0bd0087810f435"\
          "2541b143c4b981b7e18f62de8ccdf633"\
          "fc1bf037ab7cd779805e0dbcc0aae1cb"\
          "cee1afb2e027df36bc04dcecbf154336"\
          "c19f0af7e0a6472905e799f1953d2a0f"\
          "f3348ab21aa4adafd1d234441cf807c0"\
          "3a00") # SIGNATURE
      ],
      [ # 1 octet (with context)
        hexstr2bin(
          "c4eab05d357007c632f3dbb48489924d"\
          "552b08fe0c353a0d4a1f00acda2c463a"\
          "fbea67c5e8d2877c5e3bc397a659949e"\
          "f8021e954e0a12274e"), # SECRET KEY
        hexstr2bin(
          "43ba28f430cdff456ae531545f7ecd0a"\
          "c834a55d9358c0372bfa0c6c6798c086"\
          "6aea01eb00742802b8438ea4cb82169c"\
          "235160627b4c3a9480"), # PUBLIC KEY
        hexstr2bin("03"), # MESSAGE
        hexstr2bin("666f6f"), # CONTEXT
        hexstr2bin(
          "d4f8f6131770dd46f40867d6fd5d5055"\
          "de43541f8c5e35abbcd001b32a89f7d2"\
          "151f7647f11d8ca2ae279fb842d60721"\
          "7fce6e042f6815ea000c85741de5c8da"\
          "1144a6a1aba7f96de42505d7a7298524"\
          "fda538fccbbb754f578c1cad10d54d0d"\
          "5428407e85dcbc98a49155c13764e66c"\
          "3c00") # SIGNATURE
      ],
      [ # 11 octets
        hexstr2bin(
          "cd23d24f714274e744343237b93290f5"\
          "11f6425f98e64459ff203e8985083ffd"\
          "f60500553abc0e05cd02184bdb89c4cc"\
          "d67e187951267eb328"), # SECRET KEY
        hexstr2bin(
          "dcea9e78f35a1bf3499a831b10b86c90"\
          "aac01cd84b67a0109b55a36e9328b1e3"\
          "65fce161d71ce7131a543ea4cb5f7e9f"\
          "1d8b00696447001400"), # PUBLIC KEY
        hexstr2bin("0c3e544074ec63b0265e0c"), # MESSAGE
        hexstr2bin(
          "1f0a8888ce25e8d458a21130879b840a"\
          "9089d999aaba039eaf3e3afa090a09d3"\
          "89dba82c4ff2ae8ac5cdfb7c55e94d5d"\
          "961a29fe0109941e00b8dbdeea6d3b05"\
          "1068df7254c0cdc129cbe62db2dc957d"\
          "bb47b51fd3f213fb8698f064774250a5"\
          "028961c9bf8ffd973fe5d5c206492b14"\
          "0e00") # SIGNATURE
      ],
      [ # 12 octets
        hexstr2bin(
          "258cdd4ada32ed9c9ff54e63756ae582"\
          "fb8fab2ac721f2c8e676a72768513d93"\
          "9f63dddb55609133f29adf86ec9929dc"\
          "cb52c1c5fd2ff7e21b"), # SECRET KEY
        hexstr2bin(
          "3ba16da0c6f2cc1f30187740756f5e79"\
          "8d6bc5fc015d7c63cc9510ee3fd44adc"\
          "24d8e968b6e46e6f94d19b945361726b"\
          "d75e149ef09817f580"), # PUBLIC KEY
        hexstr2bin("64a65f3cdedcdd66811e2915"), # MESSAGE
        hexstr2bin(
          "7eeeab7c4e50fb799b418ee5e3197ff6"\
          "bf15d43a14c34389b59dd1a7b1b85b4a"\
          "e90438aca634bea45e3a2695f1270f07"\
          "fdcdf7c62b8efeaf00b45c2c96ba457e"\
          "b1a8bf075a3db28e5c24f6b923ed4ad7"\
          "47c3c9e03c7079efb87cb110d3a99861"\
          "e72003cbae6d6b8b827e4e6c143064ff"\
          "3c00") # SIGNATURE
      ],
      [ # 13 octets
        hexstr2bin(
          "7ef4e84544236752fbb56b8f31a23a10"\
          "e42814f5f55ca037cdcc11c64c9a3b29"\
          "49c1bb60700314611732a6c2fea98eeb"\
          "c0266a11a93970100e"), # SECRET KEY
        hexstr2bin(
          "b3da079b0aa493a5772029f0467baebe"\
          "e5a8112d9d3a22532361da294f7bb381"\
          "5c5dc59e176b4d9f381ca0938e13c6c0"\
          "7b174be65dfa578e80"), # PUBLIC KEY
        hexstr2bin("64a65f3cdedcdd66811e2915e7"), # MESSAGE
        hexstr2bin(
          "6a12066f55331b6c22acd5d5bfc5d712"\
          "28fbda80ae8dec26bdd306743c5027cb"\
          "4890810c162c027468675ecf645a8317"\
          "6c0d7323a2ccde2d80efe5a1268e8aca"\
          "1d6fbc194d3f77c44986eb4ab4177919"\
          "ad8bec33eb47bbb5fc6e28196fd1caf5"\
          "6b4e7e0ba5519234d047155ac727a105"\
          "3100") # SIGNATURE
      ],
      [ # 64 octets
        hexstr2bin(
          "d65df341ad13e008567688baedda8e9d"\
          "cdc17dc024974ea5b4227b6530e339bf"\
          "f21f99e68ca6968f3cca6dfe0fb9f4fa"\
          "b4fa135d5542ea3f01"), # SECRET KEY
        hexstr2bin(
          "df9705f58edbab802c7f8363cfe5560a"\
          "b1c6132c20a9f1dd163483a26f8ac53a"\
          "39d6808bf4a1dfbd261b099bb03b3fb5"\
          "0906cb28bd8a081f00"), # PUBLIC KEY
        hexstr2bin(
          "bd0f6a3747cd561bdddf4640a332461a"\
          "4a30a12a434cd0bf40d766d9c6d458e5"\
          "512204a30c17d1f50b5079631f64eb31"\
          "12182da3005835461113718d1a5ef944"), # MESSAGE
        hexstr2bin(
          "554bc2480860b49eab8532d2a533b7d5"\
          "78ef473eeb58c98bb2d0e1ce488a98b1"\
          "8dfde9b9b90775e67f47d4a1c3482058"\
          "efc9f40d2ca033a0801b63d45b3b722e"\
          "f552bad3b4ccb667da350192b61c508c"\
          "f7b6b5adadc2c8d9a446ef003fb05cba"\
          "5f30e88e36ec2703b349ca229c267083"\
          "3900") # SIGNATURE
      ],
      [ # 64 octets
        hexstr2bin(
          "d65df341ad13e008567688baedda8e9d"\
          "cdc17dc024974ea5b4227b6530e339bf"\
          "f21f99e68ca6968f3cca6dfe0fb9f4fa"\
          "b4fa135d5542ea3f01"), # SECRET KEY
        hexstr2bin(
          "df9705f58edbab802c7f8363cfe5560a"\
          "b1c6132c20a9f1dd163483a26f8ac53a"\
          "39d6808bf4a1dfbd261b099bb03b3fb5"\
          "0906cb28bd8a081f00"), # PUBLIC KEY
        hexstr2bin(
          "bd0f6a3747cd561bdddf4640a332461a"\
          "4a30a12a434cd0bf40d766d9c6d458e5"\
          "512204a30c17d1f50b5079631f64eb31"\
          "12182da3005835461113718d1a5ef944"), # MESSAGE
        hexstr2bin(
          "554bc2480860b49eab8532d2a533b7d5"\
          "78ef473eeb58c98bb2d0e1ce488a98b1"\
          "8dfde9b9b90775e67f47d4a1c3482058"\
          "efc9f40d2ca033a0801b63d45b3b722e"\
          "f552bad3b4ccb667da350192b61c508c"\
          "f7b6b5adadc2c8d9a446ef003fb05cba"\
          "5f30e88e36ec2703b349ca229c267083"\
          "3900") # SIGNATURE
      ],
      [ # 256 octets
        hexstr2bin(
          "2ec5fe3c17045abdb136a5e6a913e32a"\
          "b75ae68b53d2fc149b77e504132d3756"\
          "9b7e766ba74a19bd6162343a21c8590a"\
          "a9cebca9014c636df5"), # SECRET KEY
        hexstr2bin(
          "79756f014dcfe2079f5dd9e718be4171"\
          "e2ef2486a08f25186f6bff43a9936b9b"\
          "fe12402b08ae65798a3d81e22e9ec80e"\
          "7690862ef3d4ed3a00"), # PUBLIC KEY
        hexstr2bin(
          "15777532b0bdd0d1389f636c5f6b9ba7"\
          "34c90af572877e2d272dd078aa1e567c"\
          "fa80e12928bb542330e8409f31745041"\
          "07ecd5efac61ae7504dabe2a602ede89"\
          "e5cca6257a7c77e27a702b3ae39fc769"\
          "fc54f2395ae6a1178cab4738e543072f"\
          "c1c177fe71e92e25bf03e4ecb72f47b6"\
          "4d0465aaea4c7fad372536c8ba516a60"\
          "39c3c2a39f0e4d832be432dfa9a706a6"\
          "e5c7e19f397964ca4258002f7c0541b5"\
          "90316dbc5622b6b2a6fe7a4abffd9610"\
          "5eca76ea7b98816af0748c10df048ce0"\
          "12d901015a51f189f3888145c03650aa"\
          "23ce894c3bd889e030d565071c59f409"\
          "a9981b51878fd6fc110624dcbcde0bf7"\
          "a69ccce38fabdf86f3bef6044819de11"), # MESSAGE
        hexstr2bin(
          "c650ddbb0601c19ca11439e1640dd931"\
          "f43c518ea5bea70d3dcde5f4191fe53f"\
          "00cf966546b72bcc7d58be2b9badef28"\
          "743954e3a44a23f880e8d4f1cfce2d7a"\
          "61452d26da05896f0a50da66a239a8a1"\
          "88b6d825b3305ad77b73fbac0836ecc6"\
          "0987fd08527c1a8e80d5823e65cafe2a"\
          "3d00") # SIGNATURE
      ],
      [ # 1023 octets
        hexstr2bin(
          "872d093780f5d3730df7c212664b37b8"\
          "a0f24f56810daa8382cd4fa3f77634ec"\
          "44dc54f1c2ed9bea86fafb7632d8be19"\
          "9ea165f5ad55dd9ce8"), # SECRET KEY
        hexstr2bin(
          "a81b2e8a70a5ac94ffdbcc9badfc3feb"\
          "0801f258578bb114ad44ece1ec0e799d"\
          "a08effb81c5d685c0c56f64eecaef8cd"\
          "f11cc38737838cf400"), # PUBLIC KEY
        hexstr2bin(
          "6ddf802e1aae4986935f7f981ba3f035"\
          "1d6273c0a0c22c9c0e8339168e675412"\
          "a3debfaf435ed651558007db4384b650"\
          "fcc07e3b586a27a4f7a00ac8a6fec2cd"\
          "86ae4bf1570c41e6a40c931db27b2faa"\
          "15a8cedd52cff7362c4e6e23daec0fbc"\
          "3a79b6806e316efcc7b68119bf46bc76"\
          "a26067a53f296dafdbdc11c77f7777e9"\
          "72660cf4b6a9b369a6665f02e0cc9b6e"\
          "dfad136b4fabe723d2813db3136cfde9"\
          "b6d044322fee2947952e031b73ab5c60"\
          "3349b307bdc27bc6cb8b8bbd7bd32321"\
          "9b8033a581b59eadebb09b3c4f3d2277"\
          "d4f0343624acc817804728b25ab79717"\
          "2b4c5c21a22f9c7839d64300232eb66e"\
          "53f31c723fa37fe387c7d3e50bdf9813"\
          "a30e5bb12cf4cd930c40cfb4e1fc6225"\
          "92a49588794494d56d24ea4b40c89fc0"\
          "596cc9ebb961c8cb10adde976a5d602b"\
          "1c3f85b9b9a001ed3c6a4d3b1437f520"\
          "96cd1956d042a597d561a596ecd3d173"\
          "5a8d570ea0ec27225a2c4aaff26306d1"\
          "526c1af3ca6d9cf5a2c98f47e1c46db9"\
          "a33234cfd4d81f2c98538a09ebe76998"\
          "d0d8fd25997c7d255c6d66ece6fa56f1"\
          "1144950f027795e653008f4bd7ca2dee"\
          "85d8e90f3dc315130ce2a00375a318c7"\
          "c3d97be2c8ce5b6db41a6254ff264fa6"\
          "155baee3b0773c0f497c573f19bb4f42"\
          "40281f0b1f4f7be857a4e59d416c06b4"\
          "c50fa09e1810ddc6b1467baeac5a3668"\
          "d11b6ecaa901440016f389f80acc4db9"\
          "77025e7f5924388c7e340a732e554440"\
          "e76570f8dd71b7d640b3450d1fd5f041"\
          "0a18f9a3494f707c717b79b4bf75c984"\
          "00b096b21653b5d217cf3565c9597456"\
          "f70703497a078763829bc01bb1cbc8fa"\
          "04eadc9a6e3f6699587a9e75c94e5bab"\
          "0036e0b2e711392cff0047d0d6b05bd2"\
          "a588bc109718954259f1d86678a579a3"\
          "120f19cfb2963f177aeb70f2d4844826"\
          "262e51b80271272068ef5b3856fa8535"\
          "aa2a88b2d41f2a0e2fda7624c2850272"\
          "ac4a2f561f8f2f7a318bfd5caf969614"\
          "9e4ac824ad3460538fdc25421beec2cc"\
          "6818162d06bbed0c40a387192349db67"\
          "a118bada6cd5ab0140ee273204f628aa"\
          "d1c135f770279a651e24d8c14d75a605"\
          "9d76b96a6fd857def5e0b354b27ab937"\
          "a5815d16b5fae407ff18222c6d1ed263"\
          "be68c95f32d908bd895cd76207ae7264"\
          "87567f9a67dad79abec316f683b17f2d"\
          "02bf07e0ac8b5bc6162cf94697b3c27c"\
          "d1fea49b27f23ba2901871962506520c"\
          "392da8b6ad0d99f7013fbc06c2c17a56"\
          "9500c8a7696481c1cd33e9b14e40b82e"\
          "79a5f5db82571ba97bae3ad3e0479515"\
          "bb0e2b0f3bfcd1fd33034efc6245eddd"\
          "7ee2086ddae2600d8ca73e214e8c2b0b"\
          "db2b047c6a464a562ed77b73d2d841c4"\
          "b34973551257713b753632efba348169"\
          "abc90a68f42611a40126d7cb21b58695"\
          "568186f7e569d2ff0f9e745d0487dd2e"\
          "b997cafc5abf9dd102e62ff66cba87"), # MESSAGE
        hexstr2bin(
          "e301345a41a39a4d72fff8df69c98075"\
          "a0cc082b802fc9b2b6bc503f926b65bd"\
          "df7f4c8f1cb49f6396afc8a70abe6d8a"\
          "ef0db478d4c6b2970076c6a0484fe76d"\
          "76b3a97625d79f1ce240e7c576750d29"\
          "5528286f719b413de9ada3e8eb78ed57"\
          "3603ce30d8bb761785dc30dbc320869e"\
          "1a00") # SIGNATURE
      ]
    ]
    vectors.each do |vector|
      secret, pk, m, ctx, sig = vector
      if sig.nil?
        sig = ctx
        ctx = nil
      end
      _pk, sk = JOSE::JWA::Ed448.keypair(secret)
      assert_equal pk, _pk
      _sig = JOSE::JWA::Ed448.sign(m, sk, ctx)
      assert_equal sig, _sig
      assert JOSE::JWA::Ed448.verify(sig, m, pk, ctx)
    end
  end

  def test_curve448_eddsa_ed448ph
    vectors = [
      [ # TEST abc
        hexstr2bin(
          "833fe62409237b9d62ec77587520911e"\
          "9a759cec1d19755b7da901b96dca3d42"), # SECRET KEY
        hexstr2bin(
          "55ab69e205b6c7b344711f9576dfe48e"\
          "963e39e03f0fc0374465ff6b7eaa1d7d"\
          "0c95c1c36c1f4a7dc89e74fdd0dc9b34"\
          "187e1ee702b303f000"), # PUBLIC KEY
        hexstr2bin("616263"), # MESSAGE
        hexstr2bin(
          "c61f474654ce82432a6cc5c43f295b49"\
          "b5a8a256047f1edc09fe69588f75cc3b"\
          "c8bee6eaf6dc52ecac585583780fa238"\
          "2059416759a11d938079e3d0a7ed873d"\
          "4f99cdde00a35a6698e9e1763071e698"\
          "5eee73682dc91448b9058e31c1483719"\
          "f44a0d59b7d398c82c6db48c32d60db2"\
          "3e00") # SIGNATURE
      ],
      [ # TEST abc (with context)
        hexstr2bin(
          "833fe62409237b9d62ec77587520911e"\
          "9a759cec1d19755b7da901b96dca3d42"), # SECRET KEY
        hexstr2bin(
          "55ab69e205b6c7b344711f9576dfe48e"\
          "963e39e03f0fc0374465ff6b7eaa1d7d"\
          "0c95c1c36c1f4a7dc89e74fdd0dc9b34"\
          "187e1ee702b303f000"), # PUBLIC KEY
        hexstr2bin("616263"), # MESSAGE
        hexstr2bin("666f6f"), # CONTEXT
        hexstr2bin(
          "b0820f1ea13b9118d41c59de9637e92d"\
          "45878b88c72fc813a42468d90f2f323b"\
          "130e3104c9fb4746fcace1b0454cffaa"\
          "a420a405474fae5180f43b5d975e579c"\
          "059ecece8c6cbbc621baf0586db0747f"\
          "0b2a7728a6606dc86d0f157b5628e20d"\
          "e93c98afa9d5b1d4b6ba6994690db4fc"\
          "2f00") # SIGNATURE
      ]
    ]
    vectors.each do |vector|
      secret, pk, m, ctx, sig = vector
      if sig.nil?
        sig = ctx
        ctx = nil
      end
      _pk, sk = JOSE::JWA::Ed448.keypair(secret)
      assert_equal pk, _pk
      _sig = JOSE::JWA::Ed448.sign_ph(m, sk, ctx)
      assert_equal sig, _sig
      assert JOSE::JWA::Ed448.verify_ph(sig, m, pk, ctx)
    end
  end

  def test_curve448_rfc7748_curve448
    vectors = [
      [
        599189175373896402783756016145213256157230856085026129926891459468622403380588640249457727683869421921443004045221642549886377526240828, # Input scalar
        382239910814107330116229961234899377031416365240571325148346555922438025162094455820962429142971339584360034337310079791515452463053830, # Input u-coordinate
        hexstr2lint("ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239fe14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f")          # Output u-coordinate
      ],
      [
        633254335906970592779259481534862372382525155252028961056404001332122152890562527156973881968934311400345568203929409663925541994577184, # Input scalar
        622761797758325444462922068431234180649590390024811299761625153767228042600197997696167956134770744996690267634159427999832340166786063, # Input u-coordinate
        hexstr2lint("884a02576239ff7a2f2f63b2db6a9ff37047ac13568e1e30fe63c4a7ad1b3ee3a5700df34321d62077e63633c575c1c954514e99da7c179d")          # Output u-coordinate
      ]
    ]
    vectors.each do |(input_scalar, input_u_coordinate, output_u_coordinate)|
      input_scalar        = JOSE::JWA::X448.coerce_scalar_fe!(input_scalar)
      input_u_coordinate  = JOSE::JWA::X448.coerce_coordinate_fe!(input_u_coordinate)
      output_u_coordinate = JOSE::JWA::X448.coerce_coordinate_fe!(output_u_coordinate)
      assert_equal output_u_coordinate, JOSE::JWA::X448.curve448(input_scalar, input_u_coordinate)
    end
  end

  def test_curve448_rfc7748_x448
    vectors = [
      [
        hexstr2bin("9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b"), # Alice's private key, f
        hexstr2bin("9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0"), # Alice's public key, X448(f, 9)
        hexstr2bin("1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d"), # Bob's private key, g
        hexstr2bin("3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609"), # Bob's public key, X448(g, 9)
        hexstr2bin("07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a449a5037514a879d")  # Their shared secret, K
      ]
    ]
    vectors.each do |(alice_sk, alice_pk, bob_sk, bob_pk, k)|
      assert_equal k, JOSE::JWA::X448.shared_secret(alice_pk, bob_sk)
      assert_equal k, JOSE::JWA::X448.shared_secret(bob_pk, alice_sk)
    end
  end

private
  def hexstr2bin(hexstr)
    return [hexstr].pack('H*')
  end

  def hexstr2lint(hexstr)
    return OpenSSL::BN.new(hexstr2bin(hexstr).reverse, 2).to_i
  end
end
