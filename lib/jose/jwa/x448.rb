module JOSE::JWA::X448

  extend self

  C_p = ((2 ** 448) - (2 ** 224) - 1).to_bn.freeze
  C_A = 156326.to_bn.freeze
  C_order = ((2 ** 446) + 0x8335dc163bb124b65129c96fde933d8d723a70aadc873d6d54a7bb0d).to_bn.freeze
  C_cofactor = 4.to_bn.freeze
  C_u = 5.to_bn.freeze
  C_v = 355293926785568175264127502063783334808976399387714271831880898435169088786967410002932673765864550910142774147268105838985595290606362.to_bn.freeze
  C_bits = 448.to_bn.freeze
  C_bytes = ((C_bits + 7) / 8)[0].freeze
  C_bit_steps = (C_bits-1).to_i.downto(0).to_a.freeze
  C_byte_steps = (C_bytes-1).to_i.downto(0).to_a.freeze
  C_a24 = ((C_A - 2) / 4)[0].freeze
  C_scalarbytes = C_bytes
  C_coordinatebytes = C_bytes
  C_one = 1.to_bn.freeze
  C_zero = 0.to_bn.freeze
  C_F = JOSE::JWA::FieldElement.new(C_one, C_p).freeze
  C_F_one = C_F
  C_F_zero = C_F.make(C_zero).freeze
  C_F_a24 = C_F.make(C_a24).freeze

  def clamp_scalar(scalar)
    scalar = coerce_coordinate_bytes!(scalar)
    scalar.setbyte(0, scalar.getbyte(0) & 252)
    scalar.setbyte(55, scalar.getbyte(55) | 128)
    return C_F.from_bytes(scalar, C_bits)
  end

  def cswap(swap, x_2, x_3)
    iswap = (-swap.x.to_i) & 0xff
    x_2 = x_2.to_bytes(C_bits)
    x_3 = x_3.to_bytes(C_bits)
    C_byte_steps.each do |i|
      x_2i = x_2.getbyte(i)
      x_3i = x_3.getbyte(i)
      s = iswap & (x_2i ^ x_3i)
      x_2.setbyte(i, x_2i ^ s)
      x_3.setbyte(i, x_3i ^ s)
    end
    x_2 = C_F.from_bytes(x_2, C_bits)
    x_3 = C_F.from_bytes(x_3, C_bits)
    return x_2, x_3
  end

  def curve448(k, u)
    x_1 = u
    x_2 = C_F_one
    z_2 = C_F_zero
    x_3 = u
    z_3 = C_F_one
    swap = C_F_zero

    C_bit_steps.each do |t|
      k_t = (k >> t) & 1
      swap ^= k_t
      x_2, x_3 = cswap(swap, x_2, x_3)
      z_2, z_3 = cswap(swap, z_2, z_3)
      swap = k_t

      a = x_2 + z_2
      aa = a.sqr
      b = x_2 - z_2
      bb = b.sqr
      e = aa - bb
      c = x_3 + z_3
      d = x_3 - z_3
      da = d * a
      cb = c * b
      x_3 = (da + cb).sqr
      z_3 = x_1 * (da - cb).sqr
      x_2 = aa * bb
      z_2 = e * (aa + C_F_a24 * e)
    end

    x_2, x_3 = cswap(swap, x_2, x_3)
    z_2, z_3 = cswap(swap, z_2, z_3)

    return x_2 / z_2
  end

  def x448(sk, pk)
    u = coerce_coordinate_fe!(pk)
    k = clamp_scalar(sk)
    r = curve448(k, u)
    return r.to_bytes(C_bits)
  end

  def x448_base(sk)
    return x448(sk, C_u)
  end

  def keypair(sk = nil)
    sk ||= SecureRandom.random_bytes(C_bytes)
    sk = clamp_scalar(sk)
    pk = sk_to_pk(sk)
    return pk, sk.to_bytes(C_bits)
  end

  def shared_secret(pk, sk)
    return x448(sk, pk)
  end

  def sk_to_pk(sk)
    return x448_base(sk)
  end

private
  def coerce_coordinate_bn!(coordinate)
    raise ArgumentError, "coordinate size must be #{C_coordinatebytes} bytes" if not valid_coordinate?(coordinate)
    coordinate = coordinate.value if coordinate.is_a?(JOSE::JWA::FieldElement)
    coordinate = coordinate.to_bn if not coordinate.is_a?(OpenSSL::BN) and coordinate.respond_to?(:to_bn)
    coordinate = OpenSSL::BN.new(coordinate.reverse, 2) if coordinate.respond_to?(:bytesize)
    return coordinate
  end

  def coerce_scalar_bn!(scalar)
    raise ArgumentError, "scalar size must be #{C_scalarbytes} bytes" if not valid_scalar?(scalar)
    scalar = scalar.value if scalar.is_a?(JOSE::JWA::FieldElement)
    scalar = scalar.to_bn if not scalar.is_a?(OpenSSL::BN) and scalar.respond_to?(:to_bn)
    scalar = OpenSSL::BN.new(scalar.reverse, 2) if scalar.respond_to?(:bytesize)
    return scalar
  end

  def coerce_coordinate_bytes!(coordinate)
    raise ArgumentError, "coordinate size must be #{C_coordinatebytes} bytes" if not valid_coordinate?(coordinate)
    coordinate = coordinate.to_bytes(C_bits) if coordinate.is_a?(JOSE::JWA::FieldElement)
    coordinate = coordinate.to_bn if not coordinate.is_a?(OpenSSL::BN) and coordinate.respond_to?(:to_bn)
    coordinate = coordinate.to_s(2).rjust(C_bytes, JOSE::JWA::ZERO_PAD).reverse if coordinate.is_a?(OpenSSL::BN)
    return coordinate
  end

  def coerce_scalar_bytes!(scalar)
    raise ArgumentError, "scalar size must be #{C_scalarbytes} bytes" if not valid_scalar?(scalar)
    scalar = scalar.to_bytes(C_bits) if scalar.is_a?(JOSE::JWA::FieldElement)
    scalar = scalar.to_bn if not scalar.is_a?(OpenSSL::BN) and scalar.respond_to?(:to_bn)
    scalar = scalar.to_s(2).rjust(C_bytes, JOSE::JWA::ZERO_PAD).reverse if scalar.is_a?(OpenSSL::BN)
    return scalar
  end

  def coerce_coordinate_fe!(coordinate)
    return coordinate if coordinate.is_a?(JOSE::JWA::FieldElement) and coordinate.p == C_p
    coordinate = coerce_coordinate_bn!(coordinate)
    return C_F.make(coordinate)
  end

  def coerce_scalar_fe!(scalar)
    return scalar if scalar.is_a?(JOSE::JWA::FieldElement) and scalar.p == C_p
    scalar = coerce_scalar_bn!(scalar)
    return C_F.make(scalar)
  end

  def valid_coordinate?(coordinate)
    return true if coordinate.is_a?(JOSE::JWA::FieldElement) and coordinate.p == C_p
    if not coordinate.is_a?(OpenSSL::BN) and coordinate.respond_to?(:to_bn)
      coordinate = coordinate.to_bn
    end
    ubytes = 0
    if coordinate.is_a?(OpenSSL::BN)
      if coordinate.num_bytes > C_coordinatebytes
        ubytes = coordinate.num_bytes
      else
        ubytes = C_coordinatebytes
      end
    end
    ubytes = coordinate.bytesize if coordinate.respond_to?(:bytesize)
    return !!(ubytes == C_coordinatebytes)
  end

  def valid_scalar?(scalar)
    return true if scalar.is_a?(JOSE::JWA::FieldElement) and scalar.p == C_p
    if not scalar.is_a?(OpenSSL::BN) and scalar.respond_to?(:to_bn)
      scalar = scalar.to_bn
    end
    kbytes = 0
    if scalar.is_a?(OpenSSL::BN)
      if scalar.num_bytes > C_scalarbytes
        kbytes = scalar.num_bytes
      else
        kbytes = C_scalarbytes
      end
    end
    kbytes = scalar.bytesize if scalar.respond_to?(:bytesize)
    return !!(kbytes == C_scalarbytes)
  end

end
