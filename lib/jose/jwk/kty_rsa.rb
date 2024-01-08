class JOSE::JWK::KTY_RSA < Struct.new(:key)

  # JOSE::JWK callbacks

  def self.from_map(fields)
    if fields['kty'] == 'RSA' and fields['e'].is_a?(String) and fields['n'].is_a?(String)
      if fields['oth'].is_a?(Array)
        raise ArgumentError, "multi-prime RSA keys are not supported"
      elsif fields['d'].is_a?(String)
        if fields['dp'].is_a?(String) and fields['dq'].is_a?(String) and fields['p'].is_a?(String) and fields['q'].is_a?(String) and fields['qi'].is_a?(String)
          asn1_sequence = OpenSSL::ASN1::Sequence.new([
            OpenSSL::ASN1::Integer.new(0),
            OpenSSL::ASN1::Integer.new(OpenSSL::BN.new(JOSE.urlsafe_decode64(fields['n']), 2)),
            OpenSSL::ASN1::Integer.new(OpenSSL::BN.new(JOSE.urlsafe_decode64(fields['e']), 2)),
            OpenSSL::ASN1::Integer.new(OpenSSL::BN.new(JOSE.urlsafe_decode64(fields['d']), 2)),
            OpenSSL::ASN1::Integer.new(OpenSSL::BN.new(JOSE.urlsafe_decode64(fields['p']), 2)),
            OpenSSL::ASN1::Integer.new(OpenSSL::BN.new(JOSE.urlsafe_decode64(fields['q']), 2)),
            OpenSSL::ASN1::Integer.new(OpenSSL::BN.new(JOSE.urlsafe_decode64(fields['dp']), 2)),
            OpenSSL::ASN1::Integer.new(OpenSSL::BN.new(JOSE.urlsafe_decode64(fields['dq']), 2)),
            OpenSSL::ASN1::Integer.new(OpenSSL::BN.new(JOSE.urlsafe_decode64(fields['qi']), 2))
          ])
          rsa = OpenSSL::PKey::RSA.new(asn1_sequence.to_der)
          return JOSE::JWK::KTY_RSA.new(JOSE::JWK::PKeyProxy.new(rsa)), fields.except('kty', 'd', 'dp', 'dq', 'e', 'n', 'p', 'q', 'qi')
        else
          d = OpenSSL::BN.new(JOSE.urlsafe_decode64(fields['d']), 2)
          e = OpenSSL::BN.new(JOSE.urlsafe_decode64(fields['e']), 2)
          n = OpenSSL::BN.new(JOSE.urlsafe_decode64(fields['n']), 2)
          rsa = convert_sfm_to_crt(d, e, n)
          return JOSE::JWK::KTY_RSA.new(JOSE::JWK::PKeyProxy.new(rsa)), fields.except('kty', 'd', 'dp', 'dq', 'e', 'n', 'p', 'q', 'qi')
        end
      else
        asn1_sequence = OpenSSL::ASN1::Sequence.new([
          OpenSSL::ASN1::Integer.new(OpenSSL::BN.new(JOSE.urlsafe_decode64(fields['n']), 2)),
          OpenSSL::ASN1::Integer.new(OpenSSL::BN.new(JOSE.urlsafe_decode64(fields['e']), 2))
        ])
        rsa = OpenSSL::PKey::RSA.new(OpenSSL::PKey::RSA.new(asn1_sequence.to_der))
        return JOSE::JWK::KTY_RSA.new(JOSE::JWK::PKeyProxy.new(rsa)), fields.except('kty', 'e', 'n')
      end
    else
      raise ArgumentError, "invalid 'RSA' JWK"
    end
  end

  def to_key
    return key.__getobj__
  end

  def to_map(fields)
    if key.private?
      return fields.
        put('d',   JOSE.urlsafe_encode64(key.d.to_s(2))).
        put('dp',  JOSE.urlsafe_encode64(key.dmp1.to_s(2))).
        put('dq',  JOSE.urlsafe_encode64(key.dmq1.to_s(2))).
        put('e',   JOSE.urlsafe_encode64(key.e.to_s(2))).
        put('kty', 'RSA').
        put('n',   JOSE.urlsafe_encode64(key.n.to_s(2))).
        put('p',   JOSE.urlsafe_encode64(key.p.to_s(2))).
        put('q',   JOSE.urlsafe_encode64(key.q.to_s(2))).
        put('qi',  JOSE.urlsafe_encode64(key.iqmp.to_s(2))).
        put('q',   JOSE.urlsafe_encode64(key.q.to_s(2)))
    else
      return fields.
        put('e',   JOSE.urlsafe_encode64(key.e.to_s(2))).
        put('kty', 'RSA').
        put('n',   JOSE.urlsafe_encode64(key.n.to_s(2)))
    end
  end

  def to_public_map(fields)
    return to_map(fields).except('d', 'dp', 'dq', 'p', 'q', 'qi', 'oth')
  end

  def to_thumbprint_map(fields)
    return to_public_map(fields).slice('e', 'kty', 'n')
  end

  # JOSE::JWK::KTY callbacks

  def block_encryptor(fields = nil)
    if fields and fields['use'] == 'enc' and not fields['alg'].nil? and not fields['enc'].nil?
      return JOSE::Map[
        'alg' => fields['alg'],
        'enc' => fields['enc']
      ]
    else
      return JOSE::Map[
        'alg' => 'RSA-OAEP',
        'enc' => 'A128GCM'
      ]
    end
  end

  def decrypt_private(cipher_text, rsa_padding: :rsa_pkcs1_padding, rsa_oaep_md: nil)
    case rsa_padding
    when :rsa_pkcs1_padding
      return key.private_decrypt(cipher_text, OpenSSL::PKey::RSA::PKCS1_PADDING)
    when :rsa_pkcs1_oaep_padding
      rsa_oaep_md ||= OpenSSL::Digest::SHA1
      if rsa_oaep_md == OpenSSL::Digest::SHA1
        return key.private_decrypt(cipher_text, OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING)
      elsif rsa_oaep_md == OpenSSL::Digest::SHA256
        return JOSE::JWA::PKCS1.rsaes_oaep_decrypt(rsa_oaep_md, cipher_text, key)
      else
        raise ArgumentError, "unsupported RSA OAEP md: #{rsa_oaep_md.inspect}"
      end
    else
      raise ArgumentError, "unsupported RSA padding: #{rsa_padding.inspect}"
    end
  end

  def encrypt_public(plain_text, rsa_padding: :rsa_pkcs1_padding, rsa_oaep_md: nil)
    case rsa_padding
    when :rsa_pkcs1_padding
      return key.public_encrypt(plain_text, OpenSSL::PKey::RSA::PKCS1_PADDING)
    when :rsa_pkcs1_oaep_padding
      rsa_oaep_md ||= OpenSSL::Digest::SHA1
      if rsa_oaep_md == OpenSSL::Digest::SHA1
        return key.public_encrypt(plain_text, OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING)
      elsif rsa_oaep_md == OpenSSL::Digest::SHA256
        return JOSE::JWA::PKCS1.rsaes_oaep_encrypt(rsa_oaep_md, plain_text, key)
      else
        raise ArgumentError, "unsupported RSA OAEP md: #{rsa_oaep_md.inspect}"
      end
    else
      raise ArgumentError, "unsupported RSA padding: #{rsa_padding.inspect}"
    end
  end

  def self.generate_key(modulus_size, exponent_size = nil)
    if modulus_size.is_a?(Array)
      if modulus_size.length == 2 and modulus_size[0] == :rsa
        modulus_size = modulus_size[1]
      elsif modulus_size.length == 3 and modulus_size[0] == :rsa
        exponent_size = modulus_size[2]
        modulus_size  = modulus_size[1]
      end
    end
    if modulus_size.is_a?(Integer) and (exponent_size.nil? or exponent_size.is_a?(Integer))
      return from_key(OpenSSL::PKey::RSA.generate(modulus_size)) if exponent_size.nil?
      return from_key(OpenSSL::PKey::RSA.generate(modulus_size, exponent_size)) if exponent_size.is_a?(Integer)
    else
      raise ArgumentError, "'modulus_size' must be an Integer and 'exponent_size' must be nil or an Integer"
    end
  end

  def generate_key(fields)
    kty, other_fields = JOSE::JWK::KTY_RSA.generate_key([:rsa, key.n.num_bits, key.e.to_i])
    return kty, fields.delete('kid').merge(other_fields)
  end

  def key_encryptor(fields, key)
    return JOSE::JWK::KTY.key_encryptor(self, fields, key)
  end

  def sign(message, digest_type, padding: :rsa_pkcs1_padding)
    case padding
    when :rsa_pkcs1_padding
      return key.sign(digest_type.new, message)
    when :rsa_pkcs1_pss_padding
      return JOSE::JWA::PKCS1.rsassa_pss_sign(digest_type, message, key)
    else
      raise ArgumentError, "unsupported RSA padding: #{padding.inspect}"
    end
  end

  def signer(fields = nil)
    if key.private? and fields and fields['use'] == 'sig' and not fields['alg'].nil?
      return JOSE::Map['alg' => fields['alg']]
    elsif key.private?
      return JOSE::Map['alg' => 'RS256']
    else
      raise ArgumentError, "signing not supported for public keys"
    end
  end

  def verifier(fields)
    if fields and fields['use'] == 'sig' and not fields['alg'].nil?
      return [fields['alg']]
    else
      return ['PS256', 'PS384', 'PS512', 'RS256', 'RS384', 'RS512']
    end
  end

  def verify(message, digest_type, signature, padding: :rsa_pkcs1_padding)
    case padding
    when :rsa_pkcs1_padding
      return key.verify(digest_type.new, signature, message)
    when :rsa_pkcs1_pss_padding
      return JOSE::JWA::PKCS1.rsassa_pss_verify(digest_type, message, signature, key)
    else
      raise ArgumentError, "unsupported RSA padding: #{padding.inspect}"
    end
  rescue OpenSSL::PKey::PKeyError # jruby raises this error if the signature is invalid
    false
  end

  # API functions

  def self.from_key(key)
    key = key.__getobj__ if key.is_a?(JOSE::JWK::PKeyProxy)
    case key
    when OpenSSL::PKey::RSA
      return JOSE::JWK::KTY_RSA.new(JOSE::JWK::PKeyProxy.new(key)), JOSE::Map[]
    else
      raise ArgumentError, "'key' must be a OpenSSL::PKey::RSA"
    end
  end

  def to_pem(password = nil)
    return JOSE::JWK::PEM.to_binary(key, password)
  end

  # Internal functions

private
  def self.convert_sfm_to_crt(d, e, n)
    ktot = d * e - 1
    t = convert_sfm_to_crt_find_t(ktot)
    a = 2.to_bn
    k = t
    p = convert_sfm_to_crt_find_p(ktot, t, k, a, n, d)
    q, = n / p
    if q > p
      p, q = q, p
    end
    dp = d % (p - 1)
    dq = d % (q - 1)
    qi = q.mod_inverse(p)

    asn1_sequence = OpenSSL::ASN1::Sequence.new([
      OpenSSL::ASN1::Integer.new(0),
      OpenSSL::ASN1::Integer.new(n),
      OpenSSL::ASN1::Integer.new(e),
      OpenSSL::ASN1::Integer.new(d),
      OpenSSL::ASN1::Integer.new(p),
      OpenSSL::ASN1::Integer.new(q),
      OpenSSL::ASN1::Integer.new(dp),
      OpenSSL::ASN1::Integer.new(dq),
      OpenSSL::ASN1::Integer.new(qi)
    ])
    rsa = OpenSSL::PKey::RSA.new(asn1_sequence.to_der)
    return rsa
  end

  def self.convert_sfm_to_crt_find_t(ktot)
    t = ktot
    loop do
      if t > 0 and (t % 2) == 0
        t, = t / 2
      else
        break
      end
    end
    return t
  end

  def self.convert_sfm_to_crt_find_p(ktot, t, k, a, n, d)
    p = nil
    loop do
      break if not p.nil?
      loop do
        break if not p.nil?
        break if k >= ktot
        c = a.mod_exp(k, n)
        if c != 1 and c != (n - 1) and c.mod_exp(2, n) == 1
          p = (c + 1).gcd(n)
        else
          k = k * 2
        end
      end
      break if not p.nil?
      k = t
      a = a + 2
    end
    return p
  end
end
