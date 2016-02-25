# A point on (twisted) Edwards curve.
class JOSE::JWA::EdwardsPoint
  include Comparable

  attr_accessor :x, :y, :z

  def initpoint(x, y)
    @x = x
    @y = y
    @z = self.class::BASE_FIELD.make(1)
  end

  def decode_base(s, b)
    # Check that point encoding is of correct length.
    raise ArgumentError, "s must be #{(b/8)} bytes" if s.bytesize != (b / 8)
    # Extract signbit.
    s = s.dup
    xs = s.getbyte((b-1)/8) >> ((b-1) & 7)
    s.setbyte((b-1)/8, s.getbyte((b-1)/8) & ~(1 << 7))
    # Decode y. If this fails, fail.
    y = self.class::BASE_FIELD.from_bytes(s, b)
    # Try to recover x. If it does not exist, or is zero and xs is
    # wrong, fail.
    x = solve_x2(y).sqrt
    raise ArgumentError, "decode error" if x.nil? or (x.zero? and xs != x.sign)
    # If sign of x isn't correct, flip it.
    x = -x if x.sign != xs
    # Return the constructed point.
    return x, y
  end

  def encode_base(b)
    xp, yp = @x / @z, @y / @z
    # Encode y.
    s = yp.to_bytes(b)
    # Add sign bit of x to encoding.
    if xp.sign != 0
      s.setbyte((b-1)/8, s.getbyte((b-1)/8) | (1 << ((b-1) % 8)))
    end
    return s
  end

  def *(x)
    r = zero_elem
    s = self
    while x > 0
      if (x % 2) > 0
        r = r + s
      end
      s = s.double
      x = x / 2
    end
    return r
  end

  # Check two points are equal.
  def <=>(y)
    # Need to check x1/z1 == x2/z2 and similarly for y, so cross-
    # multiply to eliminate divisions.
    xn1 = @x * y.z
    xn2 = y.x * @z
    yn1 = @y * y.z
    yn2 = y.y * @z
    return yn1 <=> yn2 if xn1 == xn2
    return xn1 <=> xn2
  end
end

# A point on Edwards25519.
class JOSE::JWA::Edwards25519Point < JOSE::JWA::EdwardsPoint
  # Create a new point on curve.
  BASE_FIELD = JOSE::JWA::FieldElement.new(1, (2**255)-19).freeze
  D = (-BASE_FIELD.make(121665)/BASE_FIELD.make(121666)).freeze
  F0 = BASE_FIELD.make(0).freeze
  F1 = BASE_FIELD.make(1).freeze
  XB = BASE_FIELD.make(15112221349535400772501151409588531511454012693041857206046113283949847762202).freeze
  YB = BASE_FIELD.make(46316835694926478169428394003475163141307993866256225615783033603165251855960).freeze
  # Order of basepoint.
  L = 7237005577332262213973186563042994240857116359379907606001950938285454250989
  # The logarithm of cofactor.
  C = 3
  # The highest set bit
  N = 254
  # The coding length
  B = 256

  attr_accessor :t

  # The standard base point.
  def self.stdbase
    return new(XB, YB)
  end

  def initialize(x, y)
    # Check the point is actually on the curve.
    raise ArgumentError, "Invalid point" if y*y-x*x != F1+D*x*x*y*y
    initpoint(x, y)
    @t = x*y
  end

  # Decode a point representation.
  def decode(s)
    x, y = decode_base(s, B)
    return nil if x.nil?
    return JOSE::JWA::Edwards25519Point.new(x, y)
  end

  # Encode a point representation.
  def encode
    return encode_base(B)
  end

  def normalize
    xp, yp, zp = @x / @z, @y / @z, @z / @z
    tmp = zero_elem
    tmp.x, tmp.y, tmp.z, tmp.t = xp, yp, zp, xp * yp
    return tmp
  end

  # Construct neutral point on this curve.
  def zero_elem
    return JOSE::JWA::Edwards25519Point.new(F0, F1)
  end

  # Solve for x^2.
  def solve_x2(y)
    return ((y*y-F1)/(D*y*y+F1))
  end

  # Point addition.
  def +(y)
    # The formulas are from EFD.
    tmp = zero_elem
    zcp = @z * y.z
    a = (@y - @x) * (y.y - y.x)
    b = (@y + @x) * (y.y + y.x)
    c = (D + D) * @t * y.t
    d = zcp + zcp
    e, h = b - a, b + a
    f, g = d - c, d + c
    tmp.x, tmp.y, tmp.z, tmp.t = e * f, g * h, f * g, e * h
    return tmp
  end

  # Point doubling.
  def double
    # The formulas are from EFD.
    tmp = zero_elem
    x1s, y1s, z1s = @x * @x, @y * @y, @z * @z
    xys = @x + @y
    h = -(x1s + y1s)
    e = xys * xys + h
    g = y1s - x1s
    f = g - (z1s + z1s)
    tmp.x, tmp.y, tmp.z, tmp.t = e * f, g * h, f * g, e * h
    return tmp
  end

  def inspect
    "\n{#{@x.x},\n"\
    " #{@y.x},\n"\
    " #{@z.x},\n"\
    " #{@t.x}}"
  end

end

# A point on Edward448
class JOSE::JWA::Edwards448Point < JOSE::JWA::EdwardsPoint
  # Create a new point on curve.
  BASE_FIELD = JOSE::JWA::FieldElement.new(1, (2**448)-(2**224)-1).freeze
  D = BASE_FIELD.make(-39081).freeze
  F0 = BASE_FIELD.make(0).freeze
  F1 = BASE_FIELD.make(1).freeze
  XB = BASE_FIELD.make(224580040295924300187604334099896036246789641632564134246125461686950415467406032909029192869357953282578032075146446173674602635247710).freeze
  YB = BASE_FIELD.make(298819210078481492676017930443930673437544040154080242095928241372331506189835876003536878655418784733982303233503462500531545062832660).freeze
  # Order of basepoint.
  L = 181709681073901722637330951972001133588410340171829515070372549795146003961539585716195755291692375963310293709091662304773755859649779
  # The logarithm of cofactor.
  C = 2
  # The highest set bit
  N = 447
  # The coding length
  B = 456

  # The standard base point.
  def self.stdbase
    return new(XB, YB)
  end

  def initialize(x, y)
    # Check the point is actually on the curve.
    raise ArgumentError, "Invalid point" if y*y+x*x != F1+D*x*x*y*y
    initpoint(x, y)
  end

  # Decode a point representation.
  def decode(s)
    x, y = decode_base(s, B)
    return nil if x.nil?
    return JOSE::JWA::Edwards448Point.new(x, y)
  end

  # Encode a point representation.
  def encode
    return encode_base(B)
  end

  def normalize
    xp, yp, zp = @x / @z, @y / @z, @z / @z
    tmp = zero_elem
    tmp.x, tmp.y, tmp.z = xp, yp, zp
    return tmp
  end

  # Construct neutral point on this curve.
  def zero_elem
    return JOSE::JWA::Edwards448Point.new(F0, F1)
  end

  # Solve for x^2.
  def solve_x2(y)
    return ((y*y-F1)/(D*y*y-F1))
  end

  # Point addition.
  def +(y)
    # The formulas are from EFD.
    tmp = zero_elem
    xcp, ycp, zcp = @x * y.x, @y * y.y, @z * y.z
    b = zcp * zcp
    e = D * xcp * ycp
    f, g = b - e, b + e
    tmp.x = zcp * f * ((@x + @y) * (y.x + y.y) - xcp - ycp)
    tmp.y, tmp.z = zcp * g * (ycp - xcp), f * g
    return tmp
  end

  # Point doubling.
  def double
    # The formulas are from EFD.
    tmp = zero_elem
    x1s, y1s, z1s = @x * @x, @y * @y, @z * @z
    xys = @x + @y
    f = x1s + y1s
    j = f - (z1s + z1s)
    tmp.x, tmp.y, tmp.z = (xys * xys - x1s - y1s) * j, f * (x1s - y1s), f * j
    return tmp
  end

  def inspect
    "\n{#{@x.x},\n"\
    " #{@y.x},\n"\
    " #{@z.x}}"
  end

end
