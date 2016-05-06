class JOSE::JWK::KTY_OKP_X448 < Struct.new(:okp)

  SECRET_BYTES = 56
  PK_BYTES = 56
  SK_BYTES = SECRET_BYTES + PK_BYTES

  # JOSE::JWK callbacks

  def self.from_map(fields)
    if fields['kty'] == 'OKP' and fields['crv'] == 'X448' and fields['x'].is_a?(String)
      pk = JOSE.urlsafe_decode64(fields['x'])
      secret = nil
      if fields['d'].is_a?(String)
        secret = JOSE.urlsafe_decode64(fields['d'])
      end
      if pk.bytesize == PK_BYTES and (secret.nil? or secret.bytesize == SECRET_BYTES)
        if secret.nil?
          return JOSE::JWK::KTY_OKP_X448.new(pk), fields.except('kty', 'crv', 'x')
        else
          return JOSE::JWK::KTY_OKP_X448.new(secret + pk), fields.except('kty', 'crv', 'x', 'd')
        end
      end
    end
    raise ArgumentError, "invalid 'OKP' crv 'X448' JWK"
  end

  def to_key
    return okp
  end

  def to_map(fields)
    if okp.bytesize == SK_BYTES
      secret, pk = okp[0, SECRET_BYTES], okp[SECRET_BYTES, SK_BYTES]
      return fields.
        put('crv', 'X448').
        put('d',   JOSE.urlsafe_encode64(secret)).
        put('kty', 'OKP').
        put('x',   JOSE.urlsafe_encode64(pk))
    else
      pk = okp
      return fields.
        put('crv', 'X448').
        put('kty', 'OKP').
        put('x',   JOSE.urlsafe_encode64(pk))
    end
  end

  def to_public_map(fields)
    return to_map(fields).except('d')
  end

  def to_thumbprint_map(fields)
    return to_public_map(fields).slice('crv', 'kty', 'x')
  end

  # JOSE::JWK::KTY callbacks

  def block_encryptor(fields)
    if fields and fields['use'] == 'enc' and not fields['alg'].nil? and not fields['enc'].nil?
      jwe = JOSE::Map[
        'alg' => fields['alg'],
        'enc' => fields['enc']
      ]
      if not fields['apu'].nil?
        jwe = jwe.put('apu', fields['apu'])
      end
      if not fields['apv'].nil?
        jwe = jwe.put('apv', fields['apv'])
      end
      if not fields['epk'].nil?
        jwe = jwe.put('epk', fields['epk'])
      end
      return jwe
    else
      return JOSE::Map[
        'alg' => 'ECDH-ES',
        'enc' => 'A128GCM'
      ]
    end
  end

  def derive_key(my_sk)
    if my_sk.is_a?(JOSE::JWK) and my_sk.respond_to?(:to_okp)
      my_sk_type, my_sk = my_sk.to_okp
      raise ArgumentError, "derive_key requires a secret key of type :X448 as an argument" if my_sk_type != :X448
    end
    if my_sk.is_a?(String) and (my_sk.bytesize == SK_BYTES or my_sk.bytesize == SECRET_BYTES)
      my_secret = my_sk
      my_secret = my_sk[0, SECRET_BYTES] if my_sk.bytesize == SK_BYTES
      your_pk = okp
      your_pk = okp[SECRET_BYTES, SK_BYTES] if okp.bytesize == SK_BYTES
      return JOSE::JWA::Curve448.x448_shared_secret(your_pk, my_secret)
    else
      raise ArgumentError, "derive_key requires a secret key as an argument"
    end
  end

  def self.generate_key(okp_params)
    secret = nil
    if okp_params.is_a?(Array) and (okp_params.length == 2 or okp_params.length == 3) and okp_params[0] == :okp and okp_params[1] == :X448
      secret = okp_params[2] if okp_params.length == 3
    elsif okp_params.is_a?(String)
      secret = okp_params
    end
    if secret.nil? or (secret.is_a?(String) and secret.bytesize == SECRET_BYTES)
      pk, secret = JOSE::JWA::Curve448.x448_keypair(secret)
      sk = secret + pk
      return from_okp([:X448, sk])
    else
      raise ArgumentError, "'secret' must be nil or a String of #{SECRET_BYTES} bytes"
    end
  end

  def generate_key(fields)
    kty, other_fields = JOSE::JWK::KTY_OKP_X448.generate_key([:okp, :X448])
    return kty, fields.delete('kid').merge(other_fields)
  end

  def key_encryptor(fields, key)
    return JOSE::JWK::KTY.key_encryptor(self, fields, key)
  end

  # API functions

  def self.from_okp(okp)
    if okp.is_a?(Array) and okp.length == 2 and okp[0] == :X448 and okp[1].is_a?(String) and (okp[1].bytesize == PK_BYTES or okp[1].bytesize == SK_BYTES)
      return JOSE::JWK::KTY_OKP_X448.new(okp[1]), JOSE::Map[]
    else
      raise ArgumentError, "'okp' must be an Array in the form of [:X448, String]"
    end
  end

  def self.from_openssh_key(key)
    type, _, sk, comment = key
    if type and sk and type == 'ssh-x448' and sk.bytesize == SK_BYTES
      if comment == '' or comment.nil?
        return from_okp([:X448, sk])
      else
        kty, fields = from_okp([:X448, sk])
        return kty, fields.merge('kid' => comment)
      end
    else
      raise ArgumentError, "unrecognized openssh key type: #{type.inspect}"
    end
  end

  def to_okp
    return [:X448, okp]
  end

  def to_openssh_key(fields)
    comment = fields['kid'] || ''
    pk = JOSE::JWA::Curve448.x448_secret_to_public(okp[0, SECRET_BYTES])
    sk = okp
    return JOSE::JWK::OpenSSHKey.to_binary([
      [
        [
          ['ssh-x448', pk],
          ['ssh-x448', pk, sk, comment]
        ]
      ]
    ])
  end

end
