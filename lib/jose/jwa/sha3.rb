module JOSE::JWA::SHA3

  extend self

  ROUNDS5   = (0...5).to_a.freeze
  ROUNDS23  = (0...23).to_a.freeze
  ROUNDS24  = (0...24).to_a.freeze
  ROUNDS25  = (0...25).to_a.freeze
  ROUNDSBY5 = [0, 5, 10, 15, 20].freeze

  ROTATIONS = [
    0,1,62,28,27,36,44,6,55,20,3,10,43,25,39,41,45,15,
    21,8,18,2,61,56,14
  ].freeze

  PERMUTATION = [
    1,6,9,22,14,20,2,12,13,19,23,15,4,24,21,8,16,5,3,
    18,17,11,7,10
  ].freeze

  RC = [
    0x0000000000000001,0x0000000000008082,0x800000000000808a,
    0x8000000080008000,0x000000000000808b,0x0000000080000001,
    0x8000000080008081,0x8000000000008009,0x000000000000008a,
    0x0000000000000088,0x0000000080008009,0x000000008000000a,
    0x000000008000808b,0x800000000000008b,0x8000000000008089,
    0x8000000000008003,0x8000000000008002,0x8000000000000080,
    0x000000000000800a,0x800000008000000a,0x8000000080008081,
    0x8000000000008080,0x0000000080000001,0x8000000080008008
  ].freeze

  # Rotate a word x by b places to the left.
  def rol(x, b)
    return ((x << b) | (x >> (64 - b))) & (2**64-1)
  end

  # Do the SHA-3 state transform on state s.
  def sha3_transform(s)
    ROUNDS24.each do |rnd|
      # AddColumnParity (Theta)
      c = [0]*5
      d = [0]*5
      ROUNDS25.each do |i|
        c[i % 5] ^= s[i]
      end
      ROUNDS5.each do |i|
        d[i] = c[(i+4) % 5] ^ rol(c[(i+1) % 5], 1)
      end
      ROUNDS25.each do |i|
        s[i] ^= d[i % 5]
      end
      # RotateWords (Rho).
      ROUNDS25.each do |i|
        s[i] = rol(s[i], ROTATIONS[i])
      end
      # PermuteWords (Pi)
      t = s[PERMUTATION[0]]
      ROUNDS23.each do |i|
        s[PERMUTATION[i]] = s[PERMUTATION[i+1]]
      end
      s[PERMUTATION[-1]] = t
      # NonlinearMixRows (Chi)
      ROUNDSBY5.each do |i|
        t = [s[i],s[i+1],s[i+2],s[i+3],s[i+4],s[i],s[i+1]]
        ROUNDS5.each do |j|
          s[i+j] = t[j]^((~t[j+1])&(t[j+2]))
        end
      end
      # AddRoundConstant (Iota)
      s[0] ^= RC[rnd]
    end
    return s
  end

  # Reinterpret octet array b to word array and XOR it to state s.
  def reinterpret_to_words_and_xor(s, b)
    (0...(b.length/8)).each do |j|
      block = b[(8*j)..-1][0...8]
      block = block.pack(JOSE::JWA::UCHAR_PACK) if block.is_a?(Array)
      s[j] ^= OpenSSL::BN.new(block.reverse, 2).to_i
    end
    return s
  end

  # Reinterpret word array w to octet array and return it.
  def reinterpret_to_octets(w)
    mp = ''.force_encoding('BINARY')
    (0...(w.length)).each do |j|
      mp << OpenSSL::BN.new(w[j]).to_s(2).rjust(8, JOSE::JWA::ZERO_PAD).reverse
    end
    return mp
  end

  # (semi-)generic SHA-3 implementation
  def sha3_raw(msg, r_w, o_p, e_b)
    r_b = 8 * r_w
    s = [0]*25
    # Handle whole blocks.
    idx = 0
    blocks = msg.bytesize / r_b
    (0...blocks).each do |i|
      reinterpret_to_words_and_xor(s, msg[idx..-1][0...r_b])
      idx += r_b
      sha3_transform(s)
    end
    # Handle last block padding.
    m = msg[idx..-1].unpack(JOSE::JWA::UCHAR_PACK)
    m.push(o_p)
    while m.length < r_b
      m.push(0)
    end
    m[-1] |= 128
    # Handle padded last block.
    reinterpret_to_words_and_xor(s, m)
    sha3_transform(s)
    # Output.
    out = ''.force_encoding('BINARY')
    while out.length < e_b
      out << reinterpret_to_octets(s[0...r_w])
      sha3_transform(s)
    end
    return out[0...e_b]
  end

  # Implementations of actual SHA-3 functions.
  def sha3_224(msg)
    return sha3_raw(msg,18,6,28)
  end

  def sha3_256(msg)
    return sha3_raw(msg,17,6,32)
  end

  def sha3_384(msg)
    return sha3_raw(msg,13,6,48)
  end

  def sha3_512(msg)
    return sha3_raw(msg,9,6,64)
  end

  def shake128(msg,olen)
    return sha3_raw(msg,21,31,olen)
  end

  def shake256(msg,olen)
    return sha3_raw(msg,17,31,olen)
  end

end
