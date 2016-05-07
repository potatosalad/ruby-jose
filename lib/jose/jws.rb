module JOSE

  class SignedBinary < ::String
    # Expands a compacted signed binary or list of signed binaries into a map.
    # @see JOSE::JWS.expand
    def expand
      return JOSE::JWS.expand(self)
    end

    # Returns the decoded payload portion of a signed binary or map without verifying the signature.
    # @see JOSE::JWS.peek_payload
    def peek_payload
      return JOSE::JWS.peek_payload(self)
    end

    # Returns the decoded protected portion of a signed binary or map without verifying the signature.
    # @see JOSE::JWS.peek_protected
    def peek_protected
      return JOSE::JWS.peek_protected(self)
    end

    # Returns the decoded signature portion of a signed binary or map without verifying the signature.
    # @see JOSE::JWS.peek_signature
    def peek_signature
      return JOSE::JWS.peek_signature(self)
    end
  end

  # Immutable signed Map structure based on {JOSE::Map JOSE::Map}.
  class SignedMap < JOSE::Map
    # Compacts an expanded signed map or signed list into a binary.
    # @see JOSE::JWS.compact
    def compact
      return JOSE::JWS.compact(self)
    end
  end

  # JWS stands for JSON Web Signature which is defined in [RFC 7515](https://tools.ietf.org/html/rfc7515).
  #
  # ## Unsecured Signing Vulnerability
  #
  # The [`"none"`](https://tools.ietf.org/html/rfc7515#appendix-A.5) signing
  # algorithm is disabled by default to prevent accidental verification of empty
  # signatures (read about the vulnerability [here](https://auth0.com/blog/2015/03/31/critical-vulnerabilities-in-json-web-token-libraries/)).
  #
  # You may also enable the `"none"` algorithm by setting the `JOSE_UNSECURED_SIGNING`
  # environment variable or by using {JOSE.unsecured_signing= JOSE.unsecured_signing=}.
  #
  # ## Strict Verification Recommended
  #
  # {JOSE::JWS.verify_strict JOSE::JWS.verify_strict} is recommended over {JOSE::JWS.verify JOSE::JWS.verify} so that
  # signing algorithms may be whitelisted during verification of signed input.
  #
  # ## Algorithms
  #
  # The following algorithms are currently supported by {JOSE::JWS JOSE::JWS} (some may need the {JOSE.crypto_fallback= JOSE.crypto_fallback=} option to be enabled):
  #
  #   * `"Ed25519"`
  #   * `"Ed25519ph"`
  #   * `"Ed448"`
  #   * `"Ed448ph"`
  #   * `"ES256"`
  #   * `"ES384"`
  #   * `"ES512"`
  #   * `"HS256"`
  #   * `"HS384"`
  #   * `"HS512"`
  #   * `"PS256"`
  #   * `"PS384"`
  #   * `"PS512"`
  #   * `"RS256"`
  #   * `"RS384"`
  #   * `"RS512"`
  #   * `"none"` (disabled by default, enable with {JOSE.unsecured_signing= JOSE.unsecured_signing=})
  #
  # ## Examples
  #
  # All of the example keys generated below can be found here: [https://gist.github.com/potatosalad/925a8b74d85835e285b9](https://gist.github.com/potatosalad/925a8b74d85835e285b9)
  #
  # ### Ed25519 and Ed25519ph
  #
  #     !!!ruby
  #     # let's generate the 2 keys we'll use below
  #     jwk_ed25519   = JOSE::JWK.generate_key([:okp, :Ed25519])
  #     jwk_ed25519ph = JOSE::JWK.generate_key([:okp, :Ed25519ph])
  #
  #     # Ed25519
  #     signed_ed25519 = JOSE::JWS.sign(jwk_ed25519, "{}", { "alg" => "Ed25519" }).compact
  #     # => "eyJhbGciOiJFZDI1NTE5In0.e30.xyg2LTblm75KbLFJtROZRhEgAFJdlqH9bhx8a9LO1yvLxNLhO9fLqnFuU3ojOdbObr8bsubPkPqUfZlPkGHXCQ"
  #     JOSE::JWS.verify(jwk_ed25519, signed_ed25519).first
  #     # => true
  #
  #     # Ed25519ph
  #     signed_ed25519ph = JOSE::JWS.sign(jwk_ed25519ph, "{}", { "alg" => "Ed25519ph" }).compact
  #     # => "eyJhbGciOiJFZDI1NTE5cGgifQ.e30.R3je4TTxQvoBOupIKkel_b8eW-G8KaWmXuC14NMGSCcHCTalURtMmVqX2KbcIpFBeI-OKP3BLHNIpt1keKveDg"
  #     JOSE::JWS.verify(jwk_ed25519ph, signed_ed25519ph).first
  #     # => true
  #
  # ### Ed448 and Ed448ph
  #
  #     !!!ruby
  #     # let's generate the 2 keys we'll use below
  #     jwk_ed448   = JOSE::JWK.generate_key([:okp, :Ed448])
  #     jwk_ed448ph = JOSE::JWK.generate_key([:okp, :Ed448ph])
  #
  #     # Ed448
  #     signed_ed448 = JOSE::JWS.sign(jwk_ed448, "{}", { "alg" => "Ed448" }).compact
  #     # => "eyJhbGciOiJFZDQ0OCJ9.e30.UlqTx962FvZP1G5pZOrScRXlAB0DJI5dtZkknNTm1E70AapkONi8vzpvKd355czflQdc7uyOzTeAz0-eLvffCKgWm_zebLly7L3DLBliynQk14qgJgz0si-60mBFYOIxRghk95kk5hCsFpxpVE45jRIA"
  #     JOSE::JWS.verify(jwk_ed448, signed_ed448).first
  #     # => true
  #
  #     # Ed448ph
  #     signed_ed448ph = JOSE::JWS.sign(jwk_ed448ph, "{}", { "alg" => "Ed448ph" }).compact
  #     # => "eyJhbGciOiJFZDQ0OHBoIn0.e30._7wxQF8Am-Fg3E-KgREXBv3Gr2vqLM6ja_7hs6kA5EakCrJVQ2QiAHrr4NriLABmiPbVd7F7IiaAApyR3Ud4ak3lGcHVxSyksjJjvBUbKnSB_xkT6v_QMmx27hV08JlxskUkfvjAG0-yKGC8BXoT9R0A"
  #     JOSE::JWS.verify(jwk_ed448ph, signed_ed448ph).first
  #     # => true
  #
  # ### ES256, ES384, and ES512
  #
  #     !!!ruby
  #     # let's generate the 3 keys we'll use below
  #     jwk_es256 = JOSE::JWK.generate_key([:ec, "P-256"])
  #     jwk_es384 = JOSE::JWK.generate_key([:ec, "P-384"])
  #     jwk_es512 = JOSE::JWK.generate_key([:ec, "P-521"])
  #
  #     # ES256
  #     signed_es256 = JOSE::JWS.sign(jwk_es256, "{}", { "alg" => "ES256" }).compact
  #     # => "eyJhbGciOiJFUzI1NiJ9.e30.nb7cEQQuIi2NgcP5A468FHGG8UZg8gWZjloISyVIwNh3X6FiTTFZsvc0mL3RnulWoNJzKF6xwhae3botI1LbRg"
  #     JOSE::JWS.verify(jwk_es256, signed_es256).first
  #     # => true
  #
  #     # ES384
  #     signed_es384 = JOSE::JWS.sign(jwk_es384, "{}", { "alg" => "ES384" }).compact
  #     # => "eyJhbGciOiJFUzM4NCJ9.e30.-2kZkNe66y2SprhgvvtMa0qBrSb2imPhMYkbi_a7vx-vpEHuVKsxCpUyNVLe5_CXaHWhHyc2rNi4uEfU73c8XQB3e03rg_JOj0H5XGIGS5G9f4RmNMSCiYGwqshLSDFI"
  #     JOSE::JWS.verify(jwk_es384, signed_es384).first
  #     # => true
  #
  #     # ES512
  #     signed_es512 = JOSE::JWS.sign(jwk_es512, "{}", { "alg" => "ES512" }).compact
  #     # => "eyJhbGciOiJFUzUxMiJ9.e30.AOIw4KTq5YDu6QNrAYKtFP8R5IljAbhqXuPK1dUARPqlfc5F3mM0kmSh5KOVNHDmdCdapBv0F3b6Hl6glFDPlxpiASuSWtvvs9K8_CRfSkEzvToj8wf3WLGOarQHDwYXtlZoki1zMPGeWABwafTZNQaItNSpqYd_P9GtN0XM3AALdua0"
  #     JOSE::JWS.verify(jwk_es512, signed_es512).first
  #     # => true
  #
  # ### HS256, HS384, and HS512
  #
  #     !!!ruby
  #     # let's generate the 3 keys we'll use below
  #     jwk_hs256 = JOSE::JWK.generate_key([:oct, 16])
  #     jwk_hs384 = JOSE::JWK.generate_key([:oct, 24])
  #     jwk_hs512 = JOSE::JWK.generate_key([:oct, 32])
  #
  #     # HS256
  #     signed_hs256 = JOSE::JWS.sign(jwk_hs256, "{}", { "alg" => "HS256" }).compact
  #     # => "eyJhbGciOiJIUzI1NiJ9.e30.r2JwwMFHECoDZlrETLT-sgFT4qN3w0MLee9MrgkDwXs"
  #     JOSE::JWS.verify(jwk_hs256, signed_hs256).first
  #     # => true
  #
  #     # HS384
  #     signed_hs384 = JOSE::JWS.sign(jwk_hs384, "{}", { "alg" => "HS384" }).compact
  #     # => "eyJhbGciOiJIUzM4NCJ9.e30.brqQFXXM0XtMWDdKf0foEQcvK18swcoDkxBqCPeed_IO317_tisr60H2mz79SlNR"
  #     JOSE::JWS.verify(jwk_hs384, signed_hs384).first
  #     # => true
  #
  #     # HS512
  #     signed_hs512 = JOSE::JWS.sign(jwk_hs512, "{}", { "alg" => "HS512" }).compact
  #     # => "eyJhbGciOiJIUzUxMiJ9.e30.ge1JYomO8Fyl6sgxLbc4g3AMPbaMHLmeTl0jrUYAJZSloN9j4VyhjucX8d-RWIlMjzdG0xyklw53k1-kaTlRVQ"
  #     JOSE::JWS.verify(jwk_hs512, signed_hs512).first
  #     # => true
  #
  # ### PS256, PS384, and PS512
  #
  #     !!!ruby
  #     # let's generate the 3 keys we'll use below (cutkey must be installed as a dependency)
  #     jwk_ps256 = JOSE::JWK.generate_key([:rsa, 2048])
  #     jwk_ps384 = JOSE::JWK.generate_key([:rsa, 4096])
  #     jwk_ps512 = JOSE::JWK.generate_key([:rsa, 8192]) # this may take a few seconds
  #
  #     # PS256
  #     signed_ps256 = JOSE::JWS.sign(jwk_ps256, "{}", { "alg" => "PS256" }).compact
  #     # => "eyJhbGciOiJQUzI1NiJ9.e30.RY5A3rG2TjmdlARE57eSSSFE6plkuQPKLKsyqz3WrqKRWZgSrvROACRTzoGyrx1sNvQEZJLZ-xVhrFvP-80Q14XzQbPfYLubvn-2wcMNCmih3OVQNVtFdFjA5U2NG-sF-SWAUmm9V_DvMShFGG0qHxLX7LqT83lAIgEulgsytb0xgOjtJObBru5jLjN_uEnc7fCfnxi3my1GAtnrs9NiKvMfuIVlttvOORDFBTO2aFiCv1F-S6Xgj16rc0FGImG0x3amQcmFAD9g41KY0_KsCXgUfoiVpC6CqO6saRC4UDykks91B7Nuoxjsm3nKWa_4vKh9QJy-V8Sf0gHxK58j8Q"
  #     JOSE::JWS.verify(jwk_ps256, signed_ps256).first
  #     # => true
  #
  #     # PS384
  #     signed_ps384 = JOSE::JWS.sign(jwk_ps384, "{}", { "alg" => "PS384" }).compact
  #     # => "eyJhbGciOiJQUzM4NCJ9.e30.xmYVenIhi75hDMy3bnL6WVpVlTzYmO1ejOZeq9AkSjkp_STrdIp6uUEs9H_y7CLD9LrGYYHDNDl9WmoH6cn95WZT9KJgAVNFFYd8owY6JUHGKU1jUbLkptAgvdphVpWZ1C5fVCRt4vmp8K9f6jy3er9jCBNjl9gSBdmToFwYdXI26ZKSBjfoVm2tFFQIOThye4YQWCWHbzSho6J7d5ATje72L30zDvWXavJ-XNvof5Tkju4WQQB-ukFoqTw4yV8RVwCa-DX61I1hNrq-Zr75_iWmHak3GqNkg5ACBEjDtvtyxJizqy9KINKSlbB9jGztiWoEiXZ6wJ5sSJ6ZrSFJuQVEmns_dLqzpSHEFkWfczEV_gj9Eu_EXwMp9YQlQ3GktfXaz-mzH_jUaLmudEUskQGCiR92gK9KR6_ROQPJfD54Tkqdh6snwg6y17k8GdlTc5qMM3V84q3R6zllmhrRhV1Dlduc0MEqKcsQSX_IX21-sfiVMIcUsW73dIPXVZI2jsNlEHKqwMjWdSfjYUf3YApxSGERU3u4lRS3F0yRrZur8KWS3ToilApjg0cNg9jKas8g8C8ZPgGFYM6StVxUnXRmsJILDnsZMIPjbUDAPHhB0DwLwOB7OqGUBcItX-zwur1OVnHR7aIh1DbfWfyTIml8VIhYfGfazgXfgQVcGEM"
  #     JOSE::JWS.verify(jwk_ps384, signed_ps384).first
  #     # => true
  #
  #     # PS512
  #     signed_ps512 = JOSE::JWS.sign(jwk_ps512, "{}", { "alg" => "PS512" }).compact
  #     # => "eyJhbGciOiJQUzUxMiJ9.e30.fJe52-PF3I7UrpQamLCnmVAGkBhP0HVeJi48qZqaFc1-_tQEiYTfxuwQBDlt01GQWpjTZRb097bZF6RcrKWwRHyAo3otOZdR32emWfOHddWLL3qotj_fTaDR2-OhLixwce6mFjnHqppHH1zjCmgbKPG8S2cAadNd5w10VR-IS6LdnFRhNZOahuuB7dzCEJaSjkGfm3_9xdj3I0ZRl4fauR_LO9NQIyvMMeCFevowz1sVGG1G-I2njPrEXvxhAMp7y2mao5Yik8UUORXRjcn2Wai3umy8Yh4nHYU5qqruHjLjDwudCPNDjxjg294z1uAUpt7S0v7VbrkgUvgutTFAT-bcHywFODiycajQuqIpFp1TCUAq3Xe2yk4DTRduvPIKcPkJQnFrVkClJAU9A4D4602xpdK-z2uCgWsBVHVokf5-9ba5EqVb8BJx2xYZUIA5CdrIiTBfoe_cI5Jh92uprcWC_llio2ZJvGdQpPgwCgca7-RQ94LAmIA4u3mAndrZj_z48T2GjHbaKzl18FOPQH0XEvK_W5oypUe5NOGlz9mMGZigbFqBY2lM-7oVVYc4ZA3VFy8Dv1nWhU6DGb2NnDnQUyChllyBREuZbwrkOTQEvqqdV-6lM6VwXNu1gqc3YHly9W6u5CmsnxtvlIxsUVg679HiqdtdWxLSaIJObd9Xji56-eEkWMEA08SNy9p-F9AgHOxzoZqgrAQDEwqyEwqoAW681xLc5Vck580AQDxO9Ha4IqLIPirpO5EODQjOd8-S_SlAP5o_wz1Oh38MC5T5V13PqPuZ70dbggB4bUgVaHYC4FE4XHCqP7W3xethaPc68cY9-g9f1RUvthmnEYXSRpvyaMY3iX0txZazWIS_Jg7pNTCEaWr9JCLTZd1MiLbFowPvKYGM-z-39K31OUbq5PIScy0I9OOz9joecm8KsCesA2ysPph1E7cL7Etiw5tGhCFzcdQwm8Gm6SDwj8vCEcZUkXeZJfhlS1cJtZk1sNu3KZNndevtZjRWaXi2m4WNKVxVE-nuaF7V3GWfDemh9RXxyFK8OC8aYLIqcc2pAKJM47ANVty2ll1xaCIB3q3CKdnk5fmsnzKkQI9SjKy70p9TWT-NNoYU682KG_mZo-ByEs5CvJ8w7qysmX8Xpb2I6oSJf7S3qjbqkqtXQcV5MuQ232vk7-g42CcQGL82xvRc09TuvwnmykpKHmjUaJ4U9k9zTN3g2iTdpkvl6vbnND9uG1SBaieVeFYWCT-6VdhovEiD9bvIdA7D_R7NZO8YHBt_lfBQRle_jDyLzHSlkP6kt9dYRhrc2SNMzF_4i3iEUAihbaQYvbNsGwWrHqyGofnva20pRXwc4GxOlw"
  #     JOSE::JWS.verify(jwk_ps512, signed_ps512).first
  #     # => true
  #
  # ### RS256, RS384, and RS512
  #
  #     !!!ruby
  #     # let's generate the 3 keys we'll use below
  #     jwk_rs256 = JOSE::JWK.generate_key([:rsa, 1024])
  #     jwk_rs384 = JOSE::JWK.generate_key([:rsa, 2048])
  #     jwk_rs512 = JOSE::JWK.generate_key([:rsa, 4096])
  #
  #     # RS256
  #     signed_rs256 = JOSE::JWS.sign(jwk_rs256, "{}", { "alg" => "RS256" }).compact
  #     # => "eyJhbGciOiJSUzI1NiJ9.e30.C0J8v5R-sEe9-g_s0SMgPorCh8VDdaZ9gLpWNm1Tn1Cv2xRph1Xn9Rzm10ZCEs84sj7kxA4v28fVShQ_P1AHN83yQ2mvstkKwsuwXxr-cludx_NLQL5CKKQtTR0ITD_pxUowjfAkBYuJv0677jUj-8lGKs1P5e2dbwW9IqFe4uE"
  #     JOSE::JWS.verify(jwk_rs256, signed_rs256).first
  #     # => true
  #
  #     # RS384
  #     signed_rs384 = JOSE::JWS.sign(jwk_rs384, "{}", { "alg" => "RS384" }).compact
  #     # => "eyJhbGciOiJSUzM4NCJ9.e30.fvPxeNhO0oitOsdqFmrBgpGE7Gn_NdJ1J8F5ArKon54pdHB2v30hua9wbG4V2Hr-hNAyflaBJtoGAwIpKVkfHn-IW7d06hKw_Hv0ecG-VvZr60cK2IJnHS149Htz_652egThZh1GIKRZN1IrRVlraLMozFcWP0Ojc-L-g5XjcTFafesmV0GFGfFubAiQWEiWIgNV3822L-wPe7ZGeFe5yYsZ70WMHQQ1tSuNsm5QUOUVInOThAhJ30FRTCNFgv46l4TEF9aaI9443cKAbwzd_EavD0FpvgpwEhGyNTVx0sxiCZIYUE_jN53aSaHXB82d0xwIr2-GXlr3Y-dLwERIMw"
  #     JOSE::JWS.verify(jwk_rs384, signed_rs384).first
  #     # => true
  #
  #     # RS512
  #     signed_rs512 = JOSE::JWS.sign(jwk_rs512, "{}", { "alg" => "RS512" }).compact
  #     # => "eyJhbGciOiJSUzUxMiJ9.e30.le2_kCnmj6Y02bl16Hh5EPqmLsFkB3YZpiEfvmA6xfdg9I3QJ5uSgOejs_HpuIbItuMFUdcqtkfW45_6YKlI7plB49iWiNnWY0PLxsvbiZaSmT4R4dOUWx9KlO_Ui5SE94XkigUoFanDTHTr9bh4NpvoIaNdi_xLdC7FYA-AqZspegRcgY-QZQv4kbD3NQJtxsEiAXk8-C8CX3lF6haRlh7s4pyAmgj7SJeElsPjhPNVZ7EduhTLZfVwiLrRmzLKQ6dJ_PrZDig1lgl9jf2NjzcsFpt6lvfrMsDdIQEGyJoh53-zXiD_ltyAZGS3pX-_tHRxoAZ1SyAPkkC4cCra6wc-03sBQPoUa26xyyhrgf4h7E2l-JqhKPXT7pJv6AbRPgKUH4prEH636gpoWQrRc-JxbDIJHR0ShdL8ssf5e-rKpcVVAZKnRI64NbSKXTg-JtDxhU9QG8JVEkHqOxSeo-VSXOoExdmm8lCfqylrw7qmDxjEwOq7TGjhINyjVaK1Op_64BWVuCzgooea6G2ZvCTIEl0-k8wY8s9VC7hxSrsgCAnpWeKpIcbLQoDIoyasG-6Qb5OuSLR367eg9NAQ8WMTbrrQkm-KLNCYvMFaxmlWzBFST2JDmIr0VH9BzXRAdfG81SymuyFA7_FdpiVYwAwEGR4Q5HYEpequ38tHu3Y"
  #     JOSE::JWS.verify(jwk_rs512, signed_rs512).first
  #     # => true
  class JWS < Struct.new(:alg, :b64, :fields)

    # Decode API

    # Converts a binary or map into a {JOSE::JWS JOSE::JWS}.
    #
    #     !!!ruby
    #     JOSE::JWS.from({ "alg" => "HS256" })
    #     # => #<struct JOSE::JWS
    #     #  alg=#<struct JOSE::JWS::ALG_HMAC hmac=OpenSSL::Digest::SHA256>,
    #     #  b64=nil,
    #     #  fields=JOSE::Map[]>
    #     JOSE::JWS.from("{\"alg\":\"HS256\"}")
    #     # => #<struct JOSE::JWS
    #     #  alg=#<struct JOSE::JWS::ALG_HMAC hmac=OpenSSL::Digest::SHA256>,
    #     #  b64=nil,
    #     #  fields=JOSE::Map[]>
    #
    # Support for custom algorithms may be added by specifying `:alg` under `modules`:
    #
    #     !!!ruby
    #     JOSE::JWS.from({ "alg" => "custom" }, { alg: MyCustomAlgorithm })
    #     # => #<struct JOSE::JWS
    #     #  alg=#<MyCustomAlgorithm:0x007f8c5419ff68>,
    #     #  b64=nil,
    #     #  fields=JOSE::Map[]>
    #
    # *Note:* `MyCustomAlgorithm` must implement the methods mentioned in other alg modules.
    # @param [JOSE::Map, Hash, String, JOSE::JWS, Array<JOSE::Map, Hash, String, JOSE::JWS>] object
    # @param [Hash] modules
    # @return [JOSE::JWS, Array<JOSE::JWS>]
    def self.from(object, modules = {})
      case object
      when JOSE::Map, Hash
        return from_map(object, modules)
      when String
        return from_binary(object, modules)
      when JOSE::JWS
        return object
      when Array
        return object.map { |obj| from(obj, modules) }
      else
        raise ArgumentError, "'object' must be a Hash, String, JOSE::JWS, or Array"
      end
    end

    # Converts a binary into a {JOSE::JWS JOSE::JWS}.
    # @param [String, Array<String>] object
    # @param [Hash] modules
    # @return [JOSE::JWS, Array<JOSE::JWS>]
    def self.from_binary(object, modules = {})
      case object
      when String
        return from_map(JOSE.decode(object), modules)
      when Array
        return object.map { |obj| from_binary(obj, modules) }
      else
        raise ArgumentError, "'object' must be a String or Array"
      end
    end

    # Reads file and calls {.from_binary} to convert into a {JOSE::JWS JOSE::JWS}.
    # @param [String] object
    # @param [Hash] modules
    # @return [JOSE::JWS]
    def self.from_file(file, modules = {})
      return from_binary(File.binread(file), modules)
    end

    # Converts a map into a {JOSE::JWS JOSE::JWS}.
    # @param [JOSE::Map, Hash, Array<JOSE::Map, Hash>] object
    # @param [Hash] modules
    # @return [JOSE::JWS, Array<JOSE::JWS>]
    def self.from_map(object, modules = {})
      case object
      when JOSE::Map, Hash
        return from_fields(JOSE::JWS.new(nil, nil, JOSE::Map.new(object)), modules)
      when Array
        return object.map { |obj| from_map(obj, modules) }
      else
        raise ArgumentError, "'object' must be a Hash or Array"
      end
    end

    # Encode API

    # Converts a {JOSE::JWS JOSE::JWS} into a binary.
    # @param [JOSE::Map, Hash, String, JOSE::JWS, Array<JOSE::Map, Hash, String, JOSE::JWS>] jws
    # @return [String, Array<String>]
    def self.to_binary(jws)
      if jws.is_a?(Array)
        return from(jws).map { |obj| obj.to_binary }
      else
        return from(jws).to_binary
      end
    end

    # Converts a {JOSE::JWS JOSE::JWS} into a binary.
    # @return [String]
    def to_binary
      return JOSE.encode(to_map)
    end

    # Calls {.to_binary} on a {JOSE::JWS JOSE::JWS} and then writes the binary to `file`.
    # @param [JOSE::Map, Hash, String, JOSE::JWS] jws
    # @param [String] file
    # @return [Fixnum] bytes written
    def self.to_file(jws, file)
      return from(jws).to_file(file)
    end

    # Calls {#to_binary} on a {JOSE::JWS JOSE::JWS} and then writes the binary to `file`.
    # @param [String] file
    # @return [Fixnum] bytes written
    def to_file(file)
      return File.binwrite(file, to_binary)
    end

    # Converts a {JOSE::JWS JOSE::JWS} into a map.
    # @param [JOSE::Map, Hash, String, JOSE::JWS, Array<JOSE::Map, Hash, String, JOSE::JWS>] jws
    # @return [JOSE::Map, Array<JOSE::Map>]
    def self.to_map(jws)
      if jws.is_a?(Array)
        return from(jws).map { |obj| obj.to_map }
      else
        return from(jws).to_map
      end
    end

    # Converts a {JOSE::JWS JOSE::JWS} into a map.
    # @return [JOSE::Map]
    def to_map
      map = alg.to_map(fields)
      if b64 == false or b64 == true
        map = map.put('b64', b64)
      end
      return map
    end

    # API

    # Compacts an expanded signed map or signed list into a binary.
    #
    #     !!!ruby
    #     JOSE::JWS.compact({
    #       "payload" => "e30",
    #       "protected" => "eyJhbGciOiJIUzI1NiJ9",
    #       "signature" => "5paAJxaOXSqRUIXrP_vJXUZu2SCBH-ojgP4D6Xr6GPU"
    #     })
    #     # => "eyJhbGciOiJIUzI1NiJ9.e30.5paAJxaOXSqRUIXrP_vJXUZu2SCBH-ojgP4D6Xr6GPU"
    #
    # @see JOSE::JWS.expand
    # @param [JOSE::SignedMap, JOSE::Map, Hash] map
    # @return [JOSE::SignedBinary]
    def self.compact(map)
      if map.is_a?(Hash) or map.is_a?(JOSE::Map)
        return JOSE::SignedBinary.new([
          map['protected'] || '',
          '.',
          map['payload'] || '',
          '.',
          map['signature'] || ''
        ].join)
      else
        raise ArgumentError, "'map' must be a Hash or a JOSE::Map"
      end
    end

    # Expands a compacted signed binary or list of signed binaries into a map.
    #
    #     !!!ruby
    #     JOSE::JWS.expand("eyJhbGciOiJIUzI1NiJ9.e30.5paAJxaOXSqRUIXrP_vJXUZu2SCBH-ojgP4D6Xr6GPU")
    #     # => JOSE::SignedMap[
    #     #  "protected" => "eyJhbGciOiJIUzI1NiJ9",
    #     #  "payload" => "e30",
    #     #  "signature" => "5paAJxaOXSqRUIXrP_vJXUZu2SCBH-ojgP4D6Xr6GPU"]
    #
    # @see JOSE::JWS.compact
    # @param [JOSE::SignedBinary, String] binary
    # @return [JOSE::SignedMap]
    def self.expand(binary)
      if binary.is_a?(String)
        if binary.count('.') == 2 and (parts = binary.split('.', 3)).length == 3
          protected_binary, payload, signature = parts
          return JOSE::SignedMap[
            'payload'   => payload,
            'protected' => protected_binary,
            'signature' => signature
          ]
        else
          raise ArgumentError, "'binary' is not a valid signed String"
        end
      else
        raise ArgumentError, "'binary' must be a String"
      end
    end

    # Generates a new {JOSE::JWK JOSE::JWK} based on the algorithms of the specified {JOSE::JWS JOSE::JWS}.
    #
    #     !!!ruby
    #     JOSE::JWS.generate_key({"alg" => "HS256"})
    #     # => #<struct JOSE::JWK
    #     #  keys=nil,
    #     #  kty=
    #     #   #<struct JOSE::JWK::KTY_oct
    #     #    oct="\x96G\x1DO\xE4 \xDA\x04o\xFA\xD4\x81\xE2\xADV\xCDH0bdBDq\r+<z\xF8\xB3,\x8C\x18">,
    #     #  fields=JOSE::Map["alg" => "HS256", "use" => "sig"]>
    # @param [JOSE::Map, Hash, String, JOSE::JWS, Array<JOSE::Map, Hash, String, JOSE::JWS>] jws
    # @param [Hash] modules
    # @return [JOSE::JWK, Array<JOSE::JWK>]
    def self.generate_key(jws, modules = {})
      if jws.is_a?(Array)
        return from(jws, modules).map { |obj| obj.generate_key }
      else
        return from(jws, modules).generate_key
      end
    end

    # Generates a new {JOSE::JWK JOSE::JWK} based on the algorithms of the specified {JOSE::JWS JOSE::JWS}.
    #
    # @see JOSE::JWS.generate_key
    # @return [JOSE::JWK]
    def generate_key
      return alg.generate_key(fields)
    end

    # Merges map on right into map on left.
    # @param [JOSE::Map, Hash, String, JOSE::JWS] left
    # @param [JOSE::Map, Hash, String, JOSE::JWS] right
    # @return [JOSE::JWS]
    def self.merge(left, right)
      return from(left).merge(right)
    end

    # Merges object into current map.
    # @param [JOSE::Map, Hash, String, JOSE::JWS] object
    # @return [JOSE::JWS]
    def merge(object)
      object = case object
      when JOSE::Map, Hash
        object
      when String
        JOSE.decode(object)
      when JOSE::JWS
        object.to_map
      else
        raise ArgumentError, "'object' must be a Hash, String, or JOSE::JWS"
      end
      return JOSE::JWS.from_map(self.to_map.merge(object))
    end

    # Returns the decoded payload portion of a signed binary or map without verifying the signature.
    #
    #     !!!ruby
    #     JOSE::JWS.peek_payload("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.dMAojPMVbFvvkouYUSI9AxIRBxgqretQMCvNF7KmTHU")
    #     # => "{}"
    #
    # @param [JOSE::SignedBinary, String] signed
    # @return [String]
    def self.peek_payload(signed)
      if signed.is_a?(String)
        signed = expand(signed)
      end
      return JOSE.urlsafe_decode64(signed['payload'])
    end

    # Returns the decoded protected portion of a signed binary or map without verifying the signature.
    #
    #     !!!ruby
    #     JOSE::JWS.peek_protected("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.dMAojPMVbFvvkouYUSI9AxIRBxgqretQMCvNF7KmTHU")
    #     # => JOSE::Map["alg" => "HS256", "typ" => "JWT"]
    #
    # @param [JOSE::SignedBinary, String] signed
    # @return [JOSE::Map]
    def self.peek_protected(signed)
      if signed.is_a?(String)
        signed = expand(signed)
      end
      return JOSE::Map.new(JOSE.decode(JOSE.urlsafe_decode64(signed['protected'])))
    end

    # Returns the decoded signature portion of a signed binary or map without verifying the signature.
    #
    #     !!!ruby
    #     JOSE::JWS.peek_signature("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.dMAojPMVbFvvkouYUSI9AxIRBxgqretQMCvNF7KmTHU")
    #     # => "t\xC0(\x8C\xF3\x15l[\xEF\x92\x8B\x98Q\"=\x03\x12\x11\a\x18*\xAD\xEBP0+\xCD\x17\xB2\xA6Lu"
    #
    # @param [JOSE::SignedBinary, String] signed
    # @return [String]
    def self.peek_signature(signed)
      if signed.is_a?(String)
        signed = expand(signed)
      end
      return JOSE.urlsafe_decode64(signed['signature'])
    end

    # Signs the `plain_text` using the `jwk` and algorithm specified by the `jws`.
    #
    #     !!!ruby
    #     jwk = JOSE::JWK.from({"k" => "qUg4Yw", "kty" => "oct"})
    #     # => #<struct JOSE::JWK keys=nil, kty=#<struct JOSE::JWK::KTY_oct oct="\xA9H8c">, fields=JOSE::Map[]>
    #     JOSE::JWS.sign(jwk, "{}", { "alg" => "HS256" })
    #     # => JOSE::SignedMap[
    #     #  "signature" => "5paAJxaOXSqRUIXrP_vJXUZu2SCBH-ojgP4D6Xr6GPU",
    #     #  "protected" => "eyJhbGciOiJIUzI1NiJ9",
    #     #  "payload" => "e30"]
    #
    # If the `jwk` has a `"kid"` assigned, it will be added to the `"header"` on the signed map:
    #
    #     !!!ruby
    #     jwk = JOSE::JWK.from({"k" => "qUg4Yw", "kid" => "eyHC48MN26DvoBpkaudvOVXuI5Sy8fKMxQMYiRWmjFw", "kty" => "oct"})
    #     # => #<struct JOSE::JWK
    #     #  keys=nil,
    #     #  kty=#<struct JOSE::JWK::KTY_oct oct="\xA9H8c">,
    #     #  fields=JOSE::Map["kid" => "eyHC48MN26DvoBpkaudvOVXuI5Sy8fKMxQMYiRWmjFw"]>
    #     JOSE::JWS.sign(jwk, "test", { "alg" => "HS256" })
    #     # => JOSE::SignedMap[
    #     #  "signature" => "ZEBxtZ4SAW5hYyT7CKxH8dqynTAg-Y24QjkudQMaA_M",
    #     #  "header" => {"kid"=>"eyHC48MN26DvoBpkaudvOVXuI5Sy8fKMxQMYiRWmjFw"},
    #     #  "protected" => "eyJhbGciOiJIUzI1NiJ9",
    #     #  "payload" => "dGVzdA"]
    #
    # *Note:* Signed maps with a `"header"` or other fields will have data loss when used with {JOSE::JWS.compact JOSE::JWS.compact}.
    # @param [JOSE::JWK] jwk
    # @param [String] plain_text
    # @param [JOSE::Map, Hash, String, JOSE::JWS] jws
    # @param [JOSE::Map, Hash] header
    # @return [JOSE::SignedMap]
    def self.sign(jwk, plain_text, jws, header = nil)
      return from(jws).sign(jwk, plain_text, header)
    end

    # Signs the `plain_text` using the `jwk` and algorithm specified by the `jws`.
    # @see JOSE::JWS.sign
    # @param [JOSE::JWK] jwk
    # @param [String] plain_text
    # @param [JOSE::Map, Hash] header
    # @return [JOSE::SignedMap]
    def sign(jwk, plain_text, header = nil)
      protected_binary = JOSE.urlsafe_encode64(to_binary)
      payload = JOSE.urlsafe_encode64(plain_text)
      signing_input = signing_input(plain_text, protected_binary)
      signature = JOSE.urlsafe_encode64(alg.sign(jwk, signing_input))
      return signature_to_map(payload, protected_binary, header, jwk, signature)
    end

    # Combines `payload` and `protected_binary` based on the `"b64"` setting on the `jws` for the signing input used by {JOSE::JWS.sign JOSE::JWS.sign}.
    #
    # If `"b64"` is set to `false` on the `jws`, the raw `payload` will be used:
    #
    #     !!!ruby
    #     JOSE::JWS.signing_input("{}", { "alg" => "HS256" })
    #     # => "eyJhbGciOiJIUzI1NiJ9.e30"
    #     JOSE::JWS.signing_input("{}", { "alg" => "HS256", "b64" => false })
    #     # => "eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2V9.{}"
    #
    # @see https://tools.ietf.org/html/draft-ietf-jose-jws-signing-input-options-04 JWS Unencoded Payload Option
    # @param [String] payload
    # @param [JOSE::Map, Hash, String, JOSE::JWS] jws
    # @param [String] protected_binary
    # @return [String]
    def self.signing_input(payload, jws, protected_binary = nil)
      return from(jws).signing_input(payload, protected_binary)
    end

    # Combines `payload` and `protected_binary` based on the `"b64"` setting on the `jws` for the signing input used by {JOSE::JWS.sign JOSE::JWS.sign}.
    # @see JOSE::JWS.signing_input
    def signing_input(payload, protected_binary = nil)
      if b64 == true or b64.nil?
        payload = JOSE.urlsafe_encode64(payload)
      end
      protected_binary ||= JOSE.urlsafe_encode64(to_binary)
      return [protected_binary, '.', payload].join
    end

    # Verifies the `signed` using the `jwk`.
    #
    #     !!!ruby
    #     jwk = JOSE::JWK.from({"k" => "qUg4Yw", "kty" => "oct"})
    #     # => #<struct JOSE::JWK keys=nil, kty=#<struct JOSE::JWK::KTY_oct oct="\xA9H8c">, fields=JOSE::Map[]>
    #     JOSE::JWS.verify(jwk, "eyJhbGciOiJIUzI1NiJ9.e30.5paAJxaOXSqRUIXrP_vJXUZu2SCBH-ojgP4D6Xr6GPU")
    #     # => => [true, "{}", #<struct JOSE::JWS alg=#<struct JOSE::JWS::ALG_HMAC hmac=OpenSSL::Digest::SHA256>, b64=nil, fields=JOSE::Map[]>]
    #
    # @param [JOSE::JWK] jwk
    # @param [JOSE::SignedBinary, JOSE::SignedMap, Hash, String] signed
    # @return [[Boolean, String, JOSE::JWS]]
    def self.verify(jwk, signed)
      if signed.is_a?(String)
        signed = JOSE::JWS.expand(signed)
      end
      if signed.is_a?(Hash)
        signed = JOSE::SignedMap.new(signed)
      end
      if signed.is_a?(JOSE::Map) and signed['payload'].is_a?(String) and signed['protected'].is_a?(String) and signed['signature'].is_a?(String)
        jws = from_binary(JOSE.urlsafe_decode64(signed['protected']))
        signature = JOSE.urlsafe_decode64(signed['signature'])
        plain_text = JOSE.urlsafe_decode64(signed['payload'])
        return jws.verify(jwk, plain_text, signature, signed['protected'])
      else
        raise ArgumentError, "'signed' is not a valid signed String, Hash, or JOSE::Map"
      end
    end

    # Verifies the `signature` using the `jwk`, `plain_text`, and `protected_binary`.
    # @see JOSE::JWS.verify
    # @see JOSE::JWS.verify_strict
    # @param [JOSE::JWK] jwk
    # @param [String] plain_text
    # @param [String] signature
    # @param [String] protected_binary
    # @return [[Boolean, String, JOSE::JWS]]
    def verify(jwk, plain_text, signature, protected_binary = nil)
      protected_binary ||= JOSE.urlsafe_encode64(to_binary)
      signing_input = signing_input(plain_text, protected_binary)
      return alg.verify(jwk, signing_input, signature), plain_text, self
    end

    # Same as {JOSE::JWS.verify JOSE::JWS.verify}, but uses `allow` as a whitelist for `"alg"` which are allowed to verify against.
    #
    # If the detected algorithm is not present in `allow`, then `false` is returned.
    #
    #     !!!ruby
    #     jwk = JOSE::JWK.from({"k" => "qUg4Yw", "kty" => "oct"})
    #     # => #<struct JOSE::JWK keys=nil, kty=#<struct JOSE::JWK::KTY_oct oct="\xA9H8c">, fields=JOSE::Map[]>
    #     signed_hs256 = JOSE::JWS.sign(jwk, "{}", { "alg" => "HS256" }).compact
    #     # => "eyJhbGciOiJIUzI1NiJ9.e30.5paAJxaOXSqRUIXrP_vJXUZu2SCBH-ojgP4D6Xr6GPU"
    #     signed_hs512 = JOSE::JWS.sign(jwk, "{}", { "alg" => "HS512" }).compact
    #     # => "eyJhbGciOiJIUzUxMiJ9.e30.DN_JCks5rzQiDJJ15E6uJFskAMw-KcasGINKK_4S8xKo7W6tZ-a00ZL8UWOWgE7oHpcFrYnvSpNRldAMp19iyw"
    #     JOSE::JWS.verify_strict(jwk, ["HS256"], signed_hs256).first
    #     # => true
    #     JOSE::JWS.verify_strict(jwk, ["HS256"], signed_hs512).first
    #     # => false
    #     JOSE::JWS.verify_strict(jwk, ["HS256", "HS512"], signed_hs512).first
    #     # => true
    #
    # @param [JOSE::JWK] jwk
    # @param [Array<String>] allow
    # @param [JOSE::SignedBinary, JOSE::SignedMap, Hash, String] signed
    # @return [[Boolean, String, (JOSE::JWS, JOSE::Map)]]
    def self.verify_strict(jwk, allow, signed)
      if signed.is_a?(String)
        signed = JOSE::JWS.expand(signed)
      end
      if signed.is_a?(Hash)
        signed = JOSE::SignedMap.new(signed)
      end
      if signed.is_a?(JOSE::Map) and signed['payload'].is_a?(String) and signed['protected'].is_a?(String) and signed['signature'].is_a?(String)
        protected_map = JOSE.decode(JOSE.urlsafe_decode64(signed['protected']))
        plain_text = JOSE.urlsafe_decode64(signed['payload'])
        if allow.member?(protected_map['alg'])
          jws = from_map(protected_map)
          signature = JOSE.urlsafe_decode64(signed['signature'])
          return jws.verify(jwk, plain_text, signature, signed['protected'])
        else
          return false, plain_text, protected_map
        end
      else
        raise ArgumentError, "'signed' is not a valid signed String, Hash, or JOSE::Map"
      end
    end

  private

    EDDSA_ALG_LIST = ['Ed25519'.freeze, 'Ed25519ph'.freeze, 'Ed448'.freeze, 'Ed448ph'.freeze].freeze

    def self.from_fields(jws, modules)
      if jws.fields.has_key?('b64')
        jws.b64 = jws.fields['b64']
        jws.fields = jws.fields.delete('b64')
        return from_fields(jws, modules)
      elsif jws.fields.has_key?('alg') and jws.fields['alg'].is_a?(String)
        alg = modules[:alg] || case
        when jws.fields['alg'].start_with?('ES')
          JOSE::JWS::ALG_ECDSA
        when jws.fields['alg'].start_with?('HS')
          JOSE::JWS::ALG_HMAC
        when jws.fields['alg'].start_with?('PS')
          JOSE::JWS::ALG_RSA_PSS
        when jws.fields['alg'].start_with?('RS')
          JOSE::JWS::ALG_RSA_PKCS1_V1_5
        when EDDSA_ALG_LIST.include?(jws.fields['alg'])
          JOSE::JWS::ALG_EDDSA
        when jws.fields['alg'] == 'none'
          JOSE::JWS::ALG_none
        else
          raise ArgumentError, "unknown 'alg': #{jws.fields['alg'].inspect}"
        end
        jws.alg, jws.fields = alg.from_map(jws.fields)
        return from_fields(jws, modules)
      elsif jws.alg.nil?
        raise ArgumentError, "missing required keys: 'alg'"
      else
        return jws
      end
    end

    def signature_to_map(payload, protected_binary, header, key, signature)
      if header and header.is_a?(Hash)
        header = JOSE::Map.new(header)
      end
      header ||= JOSE::Map[]
      if key.is_a?(JOSE::JWK) and key.fields['kid'].is_a?(String)
        header = header.put('kid', key.fields['kid'])
      end
      if header.size == 0
        return JOSE::SignedMap['payload' => payload, 'protected' => protected_binary, 'signature' => signature]
      else
        return JOSE::SignedMap['header' => header.to_hash, 'payload' => payload, 'protected' => protected_binary, 'signature' => signature]
      end
    end

  end
end

require 'jose/jws/alg'
