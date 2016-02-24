class JOSE::JWA::FieldElement
  include Comparable

  attr_reader :x, :p

  def initialize(x, p)
    @p = p.to_bn
    @x = x.to_bn % @p
  end

  def <=>(y)
    return nil if not y.is_a?(JOSE::JWA::FieldElement)
    return @p <=> y.p if @p != y.p
    return value <=> y.value
  end

  def +(y)
    check_field_element(y)
    return make(@x+y.x)
  end

  def **(y)
    check_field_element(y)
    return make(@x**y.x)
  end

  def -(y)
    check_field_element(y)
    return make(@p+@x-y.x)
  end

  def -@
    return make(@p-@x)
  end

  def *(y)
    check_field_element(y)
    return make(@x*y.x)
  end

  def /(y)
    check_field_element(y)
    return self*y.inv()
  end

  def &(y)
    ival = y.x.to_i if y.is_a?(JOSE::JWA::FieldElement) and check_field_element(y)
    ival ||= y
    return make(@x.to_i & ival)
  end

  def |(y)
    ival = y.x.to_i if y.is_a?(JOSE::JWA::FieldElement) and check_field_element(y)
    ival ||= y
    return make(@x.to_i | ival)
  end

  def ^(y)
    ival = y.x.to_i if y.is_a?(JOSE::JWA::FieldElement) and check_field_element(y)
    ival ||= y
    return make(@x.to_i ^ ival)
  end

  def ~@
    return make(~@x.to_i)
  end

  def <<(y)
    ival = y.x.to_i if y.is_a?(JOSE::JWA::FieldElement) and check_field_element(y)
    ival ||= y
    return make(@x.to_i << ival)
  end

  def >>(y)
    ival = y.x.to_i if y.is_a?(JOSE::JWA::FieldElement) and check_field_element(y)
    ival ||= y
    return make(@x.to_i >> ival)
  end

  def inv
    return make(@x.mod_inverse(@p))
  end

  def sqr
    return self*self
  end

  def sqrt
    y = nil
    # Compute candidate square root.
    if (@p % 4) == 3
      y = JOSE::JWA::FieldElement.sqrt4k3(@x,@p)
    elsif (@p % 8) == 5
      y = JOSE::JWA::FieldElement.sqrt8k5(@x,@p)
    else
      raise NotImplementedError, 'sqrt(_,8k+1)'
    end
    # Check square root candidate valid.
    return y if y*y == self
    return nil
  end

  def make(ival)
    return JOSE::JWA::FieldElement.new(ival,@p)
  end

  def sign
    return @x%2
  end

  def value
    return (@p-@x)*(-1) if negative?
    return @x
  end

  def from_bytes(x, b)
    x = x.pack(JOSE::JWA::UCHAR_PACK) if x.is_a?(Array)
    rv = OpenSSL::BN.new(x.reverse, 2)# % (2**(b-1))
    raise ArgumentError, "x is larger than or equal to p" if rv >= @p
    return make(rv)
  end

  def to_bytes(b)
    return @x.to_s(2).rjust(b.to_i.div(8), JOSE::JWA::ZERO_PAD).reverse
  end

  def negative?
    return !!(sign.zero? and not zero?)
  end

  def positive?
    return !negative?
  end

  def zero?
    return @x.zero?
  end

  def self.sqrt4k3(x, p)
    return self.new(x.mod_exp(((p+1)/4)[0], p), p)
  end

  def self.sqrt8k5(x, p)
    y = x.mod_exp(((p+3)/8)[0], p)
    # If the square root exists, it is either y, or y*2^(p-1)/4.
    if y.mod_sqr(p) == (x % p)
      return self.new(y, p)
    else
      z = 2.to_bn.mod_exp(((p-1)/4)[0], p)
      return self.new(y.mod_mul(z, p), p)
    end
  end

private
  def check_field_element(y)
    raise ArgumentError, "fields don't match" if not y.is_a?(JOSE::JWA::FieldElement) or @p != y.p
    return true
  end
end
