class JOSE::JWK::KTY_OKP_Ed448ph < Struct.new(:okp)

  SECRET_BYTES = 57
  PK_BYTES = 57
  SK_BYTES = SECRET_BYTES + PK_BYTES

  # JOSE::JWK callbacks

  def self.from_map(fields)
    if fields['kty'] == 'OKP' and fields['crv'] == 'Ed448ph' and fields['x'].is_a?(String)
      pk = JOSE.urlsafe_decode64(fields['x'])
      secret = nil
      if fields['d'].is_a?(String)
        secret = JOSE.urlsafe_decode64(fields['d'])
      end
      if pk.bytesize == PK_BYTES and (secret.nil? or secret.bytesize == SECRET_BYTES)
        if secret.nil?
          return JOSE::JWK::KTY_OKP_Ed448ph.new(pk), fields.except('kty', 'crv', 'x')
        else
          return JOSE::JWK::KTY_OKP_Ed448ph.new(secret + pk), fields.except('kty', 'crv', 'x', 'd')
        end
      end
    end
    raise ArgumentError, "invalid 'OKP' crv 'Ed448ph' JWK"
  end

  def to_key
    return okp
  end

  def to_map(fields)
    if okp.bytesize == SK_BYTES
      secret, pk = okp[0, SECRET_BYTES], okp[SECRET_BYTES, SK_BYTES]
      return fields.
        put('crv', 'Ed448ph').
        put('d',   JOSE.urlsafe_encode64(secret)).
        put('kty', 'OKP').
        put('x',   JOSE.urlsafe_encode64(pk))
    else
      pk = okp
      return fields.
        put('crv', 'Ed448ph').
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

  def self.generate_key(okp_params)
    secret = nil
    if okp_params.is_a?(Array) and (okp_params.length == 2 or okp_params.length == 3) and okp_params[0] == :okp and okp_params[1] == :Ed448ph
      secret = okp_params[2] if okp_params.length == 3
    elsif okp_params.is_a?(String)
      secret = okp_params
    end
    if secret.nil? or (secret.is_a?(String) and (secret.bytesize == SECRET_BYTES))
      return from_okp([:Ed448ph, JOSE::JWA::Curve448.ed448ph_keypair(secret)[1]])
    else
      raise ArgumentError, "'secret' must be nil or a String of #{SECRET_BYTES} bytes"
    end
  end

  def generate_key(fields)
    kty, other_fields = JOSE::JWK::KTY_OKP_Ed448ph.generate_key([:okp, :Ed448ph])
    return kty, fields.delete('kid').merge(other_fields)
  end

  def key_encryptor(fields, key)
    return JOSE::JWK::KTY.key_encryptor(self, fields, key)
  end

  def sign(message, digest_type)
    raise ArgumentError, "'digest_type' must be :Ed448ph" if digest_type != :Ed448ph
    raise NotImplementedError, "Ed448ph public key cannot be used for signing" if okp.bytesize != SK_BYTES
    return JOSE::JWA::Curve448.ed448ph_sign(message, okp)
  end

  def signer(fields = nil)
    if okp.bytesize == SK_BYTES and fields and fields['use'] == 'sig' and not fields['alg'].nil?
      return JOSE::Map['alg' => fields['alg']]
    elsif okp.bytesize == SK_BYTES
      return JOSE::Map['alg' => 'Ed448ph']
    else
      raise ArgumentError, "signing not supported for public keys"
    end
  end

  def verifier(fields)
    if fields and fields['use'] == 'sig' and not fields['alg'].nil?
      return [fields['alg']]
    else
      return ['Ed448ph']
    end
  end

  def verify(message, digest_type, signature)
    raise ArgumentError, "'digest_type' must be :Ed448ph" if digest_type != :Ed448ph
    pk = okp
    pk = JOSE::JWA::Curve448.ed448ph_secret_to_public(okp) if okp.bytesize == SK_BYTES
    return JOSE::JWA::Curve448.ed448ph_verify(signature, message, pk)
  end

  # API functions

  def self.from_okp(okp)
    if okp.is_a?(Array) and okp.length == 2 and okp[0] == :Ed448ph and okp[1].is_a?(String) and (okp[1].bytesize == PK_BYTES or okp[1].bytesize == SK_BYTES)
      return JOSE::JWK::KTY_OKP_Ed448ph.new(okp[1]), JOSE::Map[]
    else
      raise ArgumentError, "'okp' must be an Array in the form of [:Ed448ph, String]"
    end
  end

  def self.from_openssh_key(key)
    type, _, sk, comment = key
    if type and sk and type == 'ssh-ed448ph' and sk.bytesize == SK_BYTES
      if comment == '' or comment.nil?
        return from_okp([:Ed448ph, sk])
      else
        kty, fields = from_okp([:Ed448ph, sk])
        return kty, fields.merge('kid' => comment)
      end
    else
      raise ArgumentError, "unrecognized openssh key type: #{type.inspect}"
    end
  end

  def to_okp
    return [:Ed448ph, okp]
  end

  def to_openssh_key(fields)
    comment = fields['kid'] || ''
    pk = JOSE::JWA::Curve448.ed448ph_secret_to_public(okp)
    sk = okp
    return JOSE::JWK::OpenSSHKey.to_binary([
      [
        [
          ['ssh-ed448ph', pk],
          ['ssh-ed448ph', pk, sk, comment]
        ]
      ]
    ])
  end

end
