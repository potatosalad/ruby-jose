class JOSE::JWK::KTY_EC < Struct.new(:key)

  # JOSE::JWK callbacks

  def self.from_map(fields)
    if fields['kty'] == 'EC' and fields['crv'].is_a?(String) and fields['x'].is_a?(String) and fields['y'].is_a?(String)
      crv = case fields['crv']
      when 'P-256'
        'prime256v1'
      when 'P-384'
        'secp384r1'
      when 'P-521'
        'secp521r1'
      else
        raise ArgumentError, "invalid 'EC' JWK"
      end
      ec = OpenSSL::PKey::EC.new(crv)
      x = JOSE.urlsafe_decode64(fields['x'])
      y = JOSE.urlsafe_decode64(fields['y'])
      ec.public_key = OpenSSL::PKey::EC::Point.new(
        OpenSSL::PKey::EC::Group.new(crv),
        OpenSSL::BN.new([0x04, x, y].pack('Ca*a*'), 2)
      )
      if fields['d'].is_a?(String)
        ec.private_key = OpenSSL::BN.new(JOSE.urlsafe_decode64(fields['d']), 2)
      end
      return JOSE::JWK::KTY_EC.new(JOSE::JWK::PKeyProxy.new(ec)), fields.except('kty', 'crv', 'd', 'x', 'y')
    else
      raise ArgumentError, "invalid 'EC' JWK"
    end
  end

  def to_key
    return key.__getobj__
  end

  def to_map(fields)
    ec_point = key.public_key.to_bn.to_s(2)
    ec_point_x, ec_point_y = case ec_point.bytesize
    when 65
      ec_point.unpack('xa32a32')
    when 97
      ec_point.unpack('xa48a48')
    when 133
      ec_point.unpack('xa66a66')
    else
      raise ArgumentError, "unhandled EC point size: #{ec_point.bytesize.inspect}"
    end
    crv = case key.group.curve_name
    when 'prime256v1', 'secp256r1'
      'P-256'
    when 'secp384r1'
      'P-384'
    when 'secp521r1'
      'P-521'
    else
      raise ArgumentError, "unhandled EC curve name: #{key.group.curve_name.inspect}"
    end
    if key.private_key?
      return fields.
        put('crv', crv).
        put('d',   JOSE.urlsafe_encode64(key.private_key.to_s(2))).
        put('kty', 'EC').
        put('x',   JOSE.urlsafe_encode64(ec_point_x)).
        put('y',   JOSE.urlsafe_encode64(ec_point_y))
    else
      return fields.
        put('crv', crv).
        put('kty', 'EC').
        put('x',   JOSE.urlsafe_encode64(ec_point_x)).
        put('y',   JOSE.urlsafe_encode64(ec_point_y))
    end
  end

  def to_public_map(fields)
    return to_map(fields).except('d')
  end

  def to_thumbprint_map(fields)
    return to_public_map(fields).slice('crv', 'kty', 'x', 'y')
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

  def derive_key(my_private_key)
    if my_private_key.is_a?(JOSE::JWK)
      my_private_key = my_private_key.to_key
    end
    if my_private_key.private_key?
      return my_private_key.dh_compute_key(key.public_key)
    else
      raise ArgumentError, "derive_key requires a private key as an argument"
    end
  end

  def self.generate_key(curve_name)
    if curve_name.is_a?(Array) and curve_name.length == 2 and curve_name[0] == :ec
      curve_name = curve_name[1]
    end
    curve_name = case curve_name
    when 'P-256'
      'prime256v1'
    when 'P-384'
      'secp384r1'
    when 'P-521'
      'secp521r1'
    else
      curve_name
    end
    if curve_name.is_a?(String)
      return from_key(OpenSSL::PKey::EC.new(curve_name).generate_key)
    else
      raise ArgumentError, "'curve_name' must be a String"
    end
  end

  def generate_key(fields)
    kty, other_fields = JOSE::JWK::KTY_EC.generate_key([:ec, key.group.curve_name])
    return kty, fields.delete('kid').merge(other_fields)
  end

  def key_encryptor(fields, key)
    return JOSE::JWK::KTY.key_encryptor(self, fields, key)
  end

  def sign(message, digest_type)
    asn1_signature = key.dsa_sign_asn1(digest_type.digest(message))
    asn1_sequence = OpenSSL::ASN1.decode(asn1_signature)
    rbin = asn1_sequence.value[0].value.to_s(2)
    sbin = asn1_sequence.value[1].value.to_s(2)
    size = [rbin.bytesize, sbin.bytesize].max
    rpad = pad(rbin, size)
    spad = pad(sbin, size)
    return rpad.concat(spad)
  end

  def signer(fields = nil)
    if key.private_key? and fields and fields['use'] == 'sig' and not fields['alg'].nil?
      return JOSE::Map['alg' => fields['alg']]
    elsif key.private_key?
      alg = case key.group.curve_name
      when 'prime256v1', 'secp256r1'
        'ES256'
      when 'secp384r1'
        'ES384'
      when 'secp521r1'
        'ES512'
      else
        raise ArgumentError, "unhandled EC curve name: #{key.group.curve_name.inspect}"
      end
      return JOSE::Map['alg' => alg]
    else
      raise ArgumentError, "signing not supported for public keys"
    end
  end

  def verifier(fields)
    if fields and fields['use'] == 'sig' and not fields['alg'].nil?
      return [fields['alg']]
    else
      alg = case key.group.curve_name
      when 'prime256v1', 'secp256r1'
        'ES256'
      when 'secp384r1'
        'ES384'
      when 'secp521r1'
        'ES512'
      else
        raise ArgumentError, "unhandled EC curve name: #{key.group.curve_name.inspect}"
      end
      return [alg]
    end
  end

  def verify(message, digest_type, signature)
    n = signature.bytesize.div(2)
    r = OpenSSL::BN.new(signature[0..(n-1)], 2)
    s = OpenSSL::BN.new(signature[n..-1], 2)
    asn1_sequence = OpenSSL::ASN1::Sequence.new([
      OpenSSL::ASN1::Integer.new(r),
      OpenSSL::ASN1::Integer.new(s)
    ])
    asn1_signature = asn1_sequence.to_der
    return key.dsa_verify_asn1(digest_type.digest(message), asn1_signature)
  end

  # API functions

  def self.from_key(key)
    key = key.__getobj__ if key.is_a?(JOSE::JWK::PKeyProxy)
    case key
    when OpenSSL::PKey::EC
      return JOSE::JWK::KTY_EC.new(JOSE::JWK::PKeyProxy.new(key)), JOSE::Map[]
    else
      raise ArgumentError, "'key' must be a OpenSSL::PKey::EC"
    end
  end

  def to_pem(password = nil)
    return JOSE::JWK::PEM.to_binary(key, password)
  end

private

  def pad(bin, size)
    if bin.bytesize == size
      return bin
    else
      return pad([0x00].pack('C').concat(bin), size)
    end
  end

end
