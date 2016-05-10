require 'rantly/minitest_extensions'
require 'rantly/shrinks'

class Rantly

  JWE_ALG_GROUPS = {
    :aesgcmkw => [
      'A128GCMKW',
      'A192GCMKW',
      'A256GCMKW'
    ],
    :aeskw => [
      'A128KW',
      'A192KW',
      'A256KW'
    ],
    :direct => [
      'dir'
    ],
    :ecdh => [
      'ECDH-ES',
      'ECDH-ES+A128KW',
      'ECDH-ES+A192KW',
      'ECDH-ES+A256KW'
    ],
    :pbes2 => [
      'PBES2-HS256+A128KW',
      'PBES2-HS384+A192KW',
      'PBES2-HS512+A256KW'
    ],
    :rsa => [
      'RSA1_5',
      'RSA-OAEP',
      'RSA-OAEP-256'
    ]
  }.freeze

  def choose_jwe_alg(*groups)
    options = if groups.empty?
      JWE_ALG_GROUPS.values.flatten
    else
      JWE_ALG_GROUPS.values_at(*groups).flatten.compact
    end
    raise ArgumentError, "'groups' may be any of #{JWE_ALG_GROUPS.keys.map(&:inspect).join(', ')}" if options.empty?
    # ECDH and RSA operations are slower, so let's restrict the probability they get chosen.
    options_faster = options.clone.delete_if { |option| option.start_with?('ECDH') or option.start_with?('RSA') }
    return freq(
      [5, :choose, *options_faster],
      [1, :choose, *options]
    )
  end

  JWE_ENC_GROUPS = {
    :aescbc => [
      'A128CBC-HS256',
      'A192CBC-HS384',
      'A256CBC-HS512'
    ],
    :aesgcm => [
      'A128GCM',
      'A192GCM',
      'A256GCM'
    ]
  }.freeze

  def choose_jwe_enc(*groups)
    options = if groups.empty?
      JWE_ENC_GROUPS.values.flatten
    else
      JWE_ENC_GROUPS.values_at(*groups).flatten.compact
    end
    raise ArgumentError, "'groups' may be any of #{JWE_ENC_GROUPS.keys.map(&:inspect).join(', ')}" if options.empty?
    return choose(*options)
  end

  JWS_ALG_GROUPS = {
    :ecdsa => [
      'ES256',
      'ES384',
      'ES512'
    ],
    :eddsa => [
      'Ed25519',
      'Ed25519ph',
      'Ed448',
      'Ed448ph'
    ],
    :hmacsha2 => [
      'HS256',
      'HS384',
      'HS512'
    ],
    :rsapkcs1_5 => [
      'RS256',
      'RS384',
      'RS512'
    ],
    :rsapss => [
      'PS256',
      'PS384',
      'PS512'
    ]
  }.freeze

  def choose_jws_alg(*groups)
    options = if groups.empty?
      JWS_ALG_GROUPS.values.flatten
    else
      JWS_ALG_GROUPS.values_at(*groups).flatten.compact
    end
    raise ArgumentError, "'groups' may be of #{JWS_ALG_GROUPS.keys.map(&:inspect).join(', ')}" if options.empty?
    # Ed448, Ed448ph, RSA PKCS#1.5, and PSS operations are slower, so let's restrict the probability they get chosen.
    options_faster = options.clone.delete_if { |option| option.start_with?('Ed448') or option.start_with?('PS') or option.start_with?('RS') }
    return freq(
      [10, :choose, *options_faster],
      [ 1, :choose, *options]
    )
  end

  def gen_jwk
    return freq(
      [10, :gen_jwk_kty_ec],
      [50, :gen_jwk_kty_oct],
      [10, :gen_jwk_kty_okp],
      [ 1, :gen_jwk_kty_rsa]
    )
  end

  def gen_jwk_kty_ec(curve_name = self.choose('P-256', 'P-384', 'P-521'))
    jwk_secret = JOSE::JWK.generate_key([:ec, curve_name])
    jwk_public = JOSE::JWK.to_public(jwk_secret)
    return Tuple.new([jwk_secret, jwk_public])
  end

  def gen_jwk_kty_oct(bytesize = self.size * 8)
    jwk_secret = JOSE::JWK.generate_key([:oct, range(0, bytesize)])
    return [jwk_secret, jwk_secret]
  end

  def gen_jwk_kty_okp(curve_name = self.choose(:Ed25519, :Ed25519ph, :Ed448, :Ed448ph, :X25519, :X448))
    jwk_secret = JOSE::JWK.generate_key([:okp, curve_name])
    jwk_public = JOSE::JWK.to_public(jwk_secret)
    return Tuple.new([jwk_secret, jwk_public])
  end

  def gen_jwk_kty_rsa(modulus_size = self.choose(2048, 4096))
    jwk_secret = RSAGenerator.cache do
      JOSE::JWK.generate_key([:rsa, modulus_size])
    end
    jwk_public = JOSE::JWK.to_public(jwk_secret)
    return Tuple.new([jwk_secret, jwk_public])
  end

  def gen_jwk_use_enc(alg = self.choose_jwe_alg, enc = self.choose_jwe_enc, extra = {})
    alg = choose_jwe_alg(*alg) if alg.is_a?(Symbol) or (alg.is_a?(Array) and alg.all? { |i| i.is_a?(Symbol) })
    enc = choose_jwe_enc(*enc) if enc.is_a?(Symbol) or (enc.is_a?(Array) and enc.all? { |i| i.is_a?(Symbol) })
    if alg.start_with?('ECDH') and extra['epk'].nil?
      extra['epk'] = freq(
        [1, :gen_jwk_kty_ec],
        [1, :gen_jwk_kty_okp, *choose(:X25519, :X448)]
      )[1].to_map
    end
    jwk_secret = RSAGenerator.cache do
      JOSE::JWE.generate_key(extra.merge({
        'alg' => alg,
        'enc' => enc
      }))
    end
    jwk_public = JOSE::JWK.to_public(jwk_secret)
    if alg.start_with?('ECDH')
      epk_secret = JOSE::JWE.generate_key(extra.merge({
        'alg' => alg,
        'enc' => enc
      }))
      epk_public = JOSE::JWK.to_public(epk_secret)
      jwk_public = [jwk_public, epk_secret]
      jwk_secret = [epk_public, jwk_secret]
    end
    return Tuple.new([jwk_secret, jwk_public])
  end

  def gen_jwk_use_sig(alg = self.choose_jws_alg, extra = {})
    alg = choose_jws_alg(*alg) if alg.is_a?(Symbol) or (alg.is_a?(Array) and alg.all? { |i| i.is_a?(Symbol) })
    jwk_secret = RSAGenerator.cache do
      JOSE::JWS.generate_key(extra.merge({
        'alg' => alg
      }))
    end
    jwk_public = JOSE::JWK.to_public(jwk_secret)
    return Tuple.new([jwk_secret, jwk_public])
  end

  def gen_jwt(n = self.size)
    return JOSE::JWT.from_map(urlsafe_base64_dict(n))
  end

  def urlsafe_base64_dict(n = self.size)
    return dict(range(0, n)) {
      [
        SecureRandom.urlsafe_base64(range(0, n)),
        SecureRandom.urlsafe_base64(range(0, n))
      ]
    }
  end

end
