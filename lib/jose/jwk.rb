module JOSE
  # JWK stands for JSON Web Key which is defined in [RFC 7517](https://tools.ietf.org/html/rfc7517).
  class JWK < Struct.new(:keys, :kty, :fields)

    # Decode API

    # Converts a binary or map into a `JOSE.JWK`.
    #
    #     !!!ruby
    #     JOSE::JWK.from({"k" => "", "kty" => "oct"})
    #     # => #<struct JOSE::JWK keys=nil, kty=#<struct JOSE::JWK::KTY_oct oct="">, fields=JOSE::Map[]>
    #     JOSE::JWK.from("{\"k\":\"\",\"kty\":\"oct\"}")
    #     # => #<struct JOSE::JWK keys=nil, kty=#<struct JOSE::JWK::KTY_oct oct="">, fields=JOSE::Map[]>
    #
    # The `"kty"` field may be overridden with a custom module that implements the {JOSE::JWK::KTY JOSE::JWK::KTY} behaviours.
    #
    # For example:
    #
    #     !!!ruby
    #     JOSE::JWK.from({ "kty" => "custom" }, { kty: MyCustomKey })
    #     # => #<struct JOSE::JWK keys=nil, kty=#<MyCustomKey:0x007f8c5419ff68>, fields=JOSE::Map[]>
    #
    # If a `key` has been specified, it will decrypt an encrypted binary or map into a {JOSE::JWK JOSE::JWK} using the specified `key`.
    #
    #     !!!ruby
    #     JOSE::JWK.from("eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJjdHkiOiJqd2sranNvbiIsImVuYyI6IkExMjhHQ00iLCJwMmMiOjQwOTYsInAycyI6Im5OQ1ZNQUktNTU5UVFtbWRFcnBsZFEifQ.Ucye69ii4dxd1ykNFlJyBVeA6xeNu4aV.2pZ4nBoxBjmdrneS.boqwdFZVNAFHk1M5P6kPYgBUgGwW32QuKzHuFA.wL9Hy6dcE_DPkUW9s5iwKA", "password")
    #     # => [#<struct JOSE::JWK keys=nil, kty=#<struct JOSE::JWK::KTY_oct oct="secret">, fields=JOSE::Map[]>,
    #     #  #<struct JOSE::JWE
    #     #   alg=
    #     #    #<struct JOSE::JWE::ALG_PBES2
    #     #     hmac=OpenSSL::Digest::SHA256,
    #     #     bits=128,
    #     #     salt="PBES2-HS256+A128KW\x00\x9C\xD0\x950\x02>\xE7\x9FPBi\x9D\x12\xBAeu",
    #     #     iter=4096>,
    #     #   enc=#<struct JOSE::JWE::ENC_AES_GCM cipher_name="aes-128-gcm", bits=128, cek_len=16, iv_len=12>,
    #     #   zip=nil,
    #     #   fields=JOSE::Map["cty" => "jwk+json"]>]
    #
    # @param [JOSE::Map, Hash, String, JOSE::JWK, Array<JOSE::Map, Hash, String, JOSE::JWK>] object
    # @param [Hash] modules
    # @param [String] key
    # @return [JOSE::JWK, Array<JOSE::JWK>]
    def self.from(object, modules = nil, key = nil)
      case object
      when JOSE::Map, Hash
        return from_map(object, modules, key)
      when String
        return from_binary(object, modules, key)
      when JOSE::JWK
        return object
      when Array
        return object.map { |obj| from(obj, modules, key) }
      else
        raise ArgumentError, "'object' must be a Hash, String, JOSE::JWK, or Array"
      end
    end

    # Converts a binary into a {JOSE::JWK JOSE::JWK}.
    #
    # @param [String, Array<String>] object
    # @param [Hash] modules
    # @param [String] key
    # @return [JOSE::JWK, Array<JOSE::JWK>]
    def self.from_binary(object, modules = nil, key = nil)
      if (modules.is_a?(String) or modules.is_a?(JOSE::JWK)) and key.nil?
        key = modules
        modules = {}
      end
      modules ||= {}
      case object
      when String
        if key
          plain_text, jwe = JOSE::JWE.block_decrypt(key, object)
          return from_binary(plain_text, modules), jwe
        else
          return from_map(JOSE.decode(object), modules)
        end
      when Array
        return object.map { |obj| from_binary(obj, modules, key) }
      else
        raise ArgumentError, "'object' must be a String or Array"
      end
    end

    # Reads file and calls {.from_binary} to convert into a {JOSE::JWK JOSE::JWK}.
    #
    # @param [String] file
    # @param [Hash] modules
    # @param [String] key
    # @return [JOSE::JWK]
    def self.from_file(file, modules = nil, key = nil)
      return from_binary(File.binread(file), modules, key)
    end

    # Converts Ruby records for EC and RSA keys into a {JOSE::JWK JOSE::JWK}.
    #
    # @param [OpenSSL::PKey] object
    # @param [Hash] modules
    # @return [JOSE::JWK]
    def self.from_key(object, modules = {})
      kty = modules[:kty] || JOSE::JWK::KTY
      return JOSE::JWK.new(nil, *kty.from_key(object))
    end

    # Converts a map into a {JOSE::JWK JOSE::JWK}.
    #
    # @param [JOSE::Map, Hash, Array<JOSE::Map, Hash>] object
    # @param [Hash] modules
    # @param [String] key
    # @return [JOSE::JWK, Array<JOSE::JWK>]
    def self.from_map(object, modules = nil, key = nil)
      if (modules.is_a?(String) or modules.is_a?(JOSE::JWK)) and key.nil?
        key = modules
        modules = {}
      end
      modules ||= {}
      case object
      when JOSE::Map, Hash
        if key
          plain_text, jwe = JOSE::JWE.block_decrypt(key, object)
          return from_binary(plain_text, modules), jwe
        else
          return from_fields(JOSE::JWK.new(nil, nil, JOSE::Map.new(object)), modules)
        end
      when Array
        return object.map { |obj| from_map(obj, modules, key) }
      else
        raise ArgumentError, "'object' must be a JOSE::Map, Hash, or Array"
      end
    end

    # Converts an arbitrary binary into a {JOSE::JWK JOSE::JWK} with `"kty"` of `"oct"`.
    #
    # @param [String] object
    # @param [Hash] modules
    # @return [JOSE::JWK]
    def self.from_oct(object, modules = {})
      kty = modules[:kty] || JOSE::JWK::KTY_oct
      return JOSE::JWK.new(nil, *kty.from_oct(object))
    end

    # Reads file and calls {JOSE::JWK.from_oct JOSE::JWK.from_oct} to convert into a {JOSE::JWK JOSE::JWK}.
    #
    # @param [String] file
    # @param [Hash] modules
    # @return [JOSE::JWK]
    def self.from_oct_file(file, modules = {})
      return from_oct(File.binread(file), modules)
    end

    # Converts an octet key pair into a {JOSE::JWK JOSE::JWK} with `"kty"` of `"OKP"`.
    #
    # @param [Array] object
    # @param [Hash] modules
    # @return [JOSE::JWK]
    def self.from_okp(object, modules = {})
      raise ArgumentError, "object must be an Array of length 2" if not object.is_a?(Array) or object.length != 2
      kty = modules[:kty] || case object[0]
      when :Ed25519
        JOSE::JWK::KTY_OKP_Ed25519
      when :Ed25519ph
        JOSE::JWK::KTY_OKP_Ed25519ph
      when :Ed448
        JOSE::JWK::KTY_OKP_Ed448
      when :Ed448ph
        JOSE::JWK::KTY_OKP_Ed448ph
      when :X25519
        JOSE::JWK::KTY_OKP_X25519
      when :X448
        JOSE::JWK::KTY_OKP_X448
      else
        raise ArgumentError, "unrecognized :okp object"
      end
      return JOSE::JWK.new(nil, *kty.from_okp(object))
    end

    # Converts an openssh key into a {JOSE::JWK JOSE::JWK} with `"kty"` of `"OKP"`.
    #
    # @param [String, Array] object
    # @param [Hash] modules
    # @return [JOSE::JWK]
    def self.from_openssh_key(object, modules = {})
      raise ArgumentError, "object must be a String or Array" if not object.is_a?(String) and not object.is_a?(Array)
      keys = object
      if object.is_a?(String)
        keys = JOSE::JWK::OpenSSHKey.from_binary(object)
      end
      ((pk_type, pk), key), = keys[0]
      sk_type, sk_pk, = key
      if pk_type and pk and key and sk_type and sk_pk and pk_type == sk_type and pk == sk_pk
        kty = modules[:kty] || case pk_type
        when 'ssh-ed25519'
          JOSE::JWK::KTY_OKP_Ed25519
        when 'ssh-ed25519ph'
          JOSE::JWK::KTY_OKP_Ed25519ph
        when 'ssh-ed448'
          JOSE::JWK::KTY_OKP_Ed448
        when 'ssh-ed448ph'
          JOSE::JWK::KTY_OKP_Ed448ph
        when 'ssh-x25519'
          JOSE::JWK::KTY_OKP_X25519
        when 'ssh-x448'
          JOSE::JWK::KTY_OKP_X448
        else
          raise ArgumentError, "unrecognized openssh key type: #{pk_type.inspect}"
        end
        return JOSE::JWK.new(nil, *kty.from_openssh_key(key))
      else
        raise ArgumentError, "unrecognized openssh key format"
      end
    end

    # Reads file and calls {JOSE::JWK.from_openssh_key JOSE::JWK.from_openssh_key} to convert into a {JOSE::JWK JOSE::JWK}.
    #
    # @param [String] file
    # @param [Hash] modules
    # @return [JOSE::JWK]
    def self.from_openssh_key_file(file, modules = {})
      return from_openssh_key(File.binread(file), modules)
    end

    # Converts a PEM (Privacy Enhanced Email) binary into a {JOSE::JWK JOSE::JWK}.
    #
    # If `password` is present, decrypts an encrypted PEM (Privacy Enhanced Email) binary into a {JOSE::JWK JOSE::JWK} using `password`.
    #
    # @param [String] object
    # @param [Hash] modules
    # @param [String] password
    # @return [JOSE::JWK]
    def self.from_pem(object, modules = nil, password = nil)
      if modules.is_a?(String) and password.nil?
        password = modules
        modules  = {}
      end
      modules ||= {}
      kty = modules[:kty] || JOSE::JWK::PEM
      return JOSE::JWK.new(nil, *kty.from_binary(object, password))
    end

    # Reads file and calls {JOSE::JWK.from_pem JOSE::JWK.from_pem} to convert into a {JOSE::JWK JOSE::JWK}.
    #
    # @param [String] file
    # @param [Hash] modules
    # @param [String] password
    # @return [JOSE::JWK]
    def self.from_pem_file(file, modules = nil, password = nil)
      return from_pem(File.binread(file), modules, password)
    end

    # Encode API

    # Converts a {JOSE::JWK JOSE::JWK} into a binary.
    #
    # @param [JOSE::JWK, Array<JOSE::JWK>] jwk
    # @param [String] key
    # @param [JOSE::JWE] jwe
    # @return [String, JOSE::EncryptedBinary, Array<String, JOSE::EncryptedBinary>]
    def self.to_binary(jwk, key = nil, jwe = nil)
      if jwk.is_a?(Array)
        return jwk.map { |obj| from(obj).to_binary(key, jwe) }
      else
        return from(jwk).to_binary(key, jwe)
      end
    end

    # Converts a {JOSE::JWK JOSE::JWK} into a binary.
    #
    # @param [String] key
    # @param [JOSE::JWE] jwe
    # @return [String, JOSE::EncryptedBinary]
    def to_binary(key = nil, jwe = nil)
      if not key.nil?
        jwe ||= kty.key_encryptor(fields, key)
      end
      if key and jwe
        return to_map(key, jwe).compact
      else
        return JOSE.encode(to_map)
      end
    end

    # Calls {JOSE::JWK.to_binary JOSE::JWK.to_binary} on a {JOSE::JWK JOSE::JWK} and then writes the binary to `file`.
    #
    # @param [JOSE::Map, Hash, String, JOSE::JWK] jwk
    # @param [String] file
    # @param [String] key
    # @param [JOSE::JWE] jwe
    # @return [Fixnum] bytes written
    def self.to_file(jwk, file, key = nil, jwe = nil)
      return from(jwk).to_file(file, key, jwe)
    end

    # Calls {JOSE::JWK.to_binary JOSE::JWK.to_binary} on a {JOSE::JWK JOSE::JWK} and then writes the binary to `file`.
    #
    # @param [String] file
    # @param [String] key
    # @param [JOSE::JWE] jwe
    # @return [Fixnum] bytes written
    def to_file(file, key = nil, jwe = nil)
      return File.binwrite(file, to_binary(key, jwe))
    end

    # Converts a {JOSE::JWK JOSE::JWK} into the raw key format.
    #
    # @param [JOSE::JWK] jwk
    # @return [OpenSSL::PKey, Object]
    def self.to_key(jwk)
      return from(jwk).to_key
    end

    # Converts a {JOSE::JWK JOSE::JWK} into the raw key format.
    #
    # @return [OpenSSL::PKey, Object]
    def to_key
      return kty.to_key
    end

    # Converts a {JOSE::JWK JOSE::JWK} into a map.
    #
    # @param [JOSE::Map, Hash, String, JOSE::JWK, Array<JOSE::Map, Hash, String, JOSE::JWK>] jwk
    # @param [String] key
    # @param [JOSE::JWE] jwe
    # @return [JOSE::Map, Array<JOSE::Map>]
    def self.to_map(jwk, key = nil, jwe = nil)
      if jwk.is_a?(Array)
        return from(jwk).map { |obj| obj.to_map(key, jwe) }
      else
        return from(jwk).to_map(key, jwe)
      end
    end

    # Converts a {JOSE::JWK JOSE::JWK} into a map.
    #
    # @param [String] key
    # @param [JOSE::JWE] jwe
    # @return [JOSE::Map]
    def to_map(key = nil, jwe = nil)
      if not key.nil?
        jwe ||= kty.key_encryptor(fields, key)
      end
      if key and jwe
        return JOSE::JWE.block_encrypt(key, to_binary, jwe)
      elsif kty.nil? and keys
        return keys.to_map(fields)
      else
        return kty.to_map(fields)
      end
    end

    # Converts a {JOSE::JWK JOSE::JWK} into a raw binary octet.
    #
    # @param [JOSE::Map, Hash, String, JOSE::JWK, Array<JOSE::Map, Hash, String, JOSE::JWK>] jwk
    # @return [String, Array<String>]
    def self.to_oct(jwk)
      if jwk.is_a?(Array)
        return from(jwk).map { |obj| obj.to_oct }
      else
        return from(jwk).to_oct
      end
    end

    # Converts a {JOSE::JWK JOSE::JWK} into a raw binary octet.
    #
    # @return [String]
    def to_oct
      return kty.to_oct
    end

    # Calls {JOSE::JWK.to_oct JOSE::JWK.to_oct} on a {JOSE::JWK JOSE::JWK} and then writes the binary to `file`.
    #
    # @param [JOSE::Map, Hash, String, JOSE::JWK] jwk
    # @param [String] file
    # @return [Fixnum] bytes written
    def self.to_oct_file(jwk, file)
      return from(jwk).to_oct_file(file)
    end

    # Calls {JOSE::JWK#to_oct JOSE::JWK#to_oct} on a {JOSE::JWK JOSE::JWK} and then writes the binary to `file`.
    #
    # @param [String] file
    # @return [Fixnum] bytes written
    def to_oct_file(file)
      return File.binwrite(file, to_oct)
    end

    # Converts a {JOSE::JWK JOSE::JWK} into an octet key pair.
    #
    # @param [JOSE::Map, Hash, String, JOSE::JWK, Array<JOSE::Map, Hash, String, JOSE::JWK>] jwk
    # @return [Object, Array<Object>]
    def self.to_okp(jwk)
      if jwk.is_a?(Array)
        return from(jwk).map { |obj| obj.to_okp }
      else
        return from(jwk).to_okp
      end
    end

    # Converts a {JOSE::JWK JOSE::JWK} into an octet key pair.
    #
    # @return [String]
    def to_okp
      return kty.to_okp
    end

    # Converts a {JOSE::JWK JOSE::JWK} into an OpenSSH key binary.
    #
    # @param [JOSE::Map, Hash, String, JOSE::JWK, Array<JOSE::Map, Hash, String, JOSE::JWK>] jwk
    # @return [Object, Array<Object>]
    def self.to_openssh_key(jwk)
      if jwk.is_a?(Array)
        return from(jwk).map { |obj| obj.to_openssh_key }
      else
        return from(jwk).to_openssh_key
      end
    end

    # Converts a {JOSE::JWK JOSE::JWK} into an OpenSSH key binary.
    #
    # @return [Object]
    def to_openssh_key
      return kty.to_openssh_key(fields)
    end

    # Calls {JOSE::JWK.to_openssh_key JOSE::JWK.to_openssh_key} on a {JOSE::JWK JOSE::JWK} and then writes the binary to `file`.
    #
    # @param [JOSE::Map, Hash, String, JOSE::JWK] jwk
    # @param [String] file
    # @return [Fixnum] bytes written
    def self.to_openssh_key_file(jwk, file)
      return from(jwk).to_openssh_key_file(file)
    end

    # Calls {JOSE::JWK#to_openssh_key JOSE::JWK#to_openssh_key} on a {JOSE::JWK JOSE::JWK} and then writes the binary to `file`.
    #
    # @param [String] file
    # @return [Fixnum] bytes written
    def to_openssh_key_file(file)
      return File.binwrite(file, to_openssh_key)
    end

    # Converts a {JOSE::JWK JOSE::JWK} into a PEM (Privacy Enhanced Email) binary.
    #
    # @param [JOSE::Map, Hash, String, JOSE::JWK, Array<JOSE::Map, Hash, String, JOSE::JWK>] jwk
    # @param [String] password
    # @return [String, Array<String>]
    def self.to_pem(jwk, password = nil)
      if jwk.is_a?(Array)
        return from(jwk).map { |obj| obj.to_pem(password) }
      else
        return from(jwk).to_pem(password)
      end
    end

    # Converts a {JOSE::JWK JOSE::JWK} into a PEM (Privacy Enhanced Email) binary.
    #
    # @param [String] password
    # @return [String]
    def to_pem(password = nil)
      return kty.to_pem(password)
    end

    # Calls {JOSE::JWK.to_pem JOSE::JWK.to_pem} on a {JOSE::JWK JOSE::JWK} and then writes the binary to `file`.
    #
    # @param [JOSE::Map, Hash, String, JOSE::JWK] jwk
    # @param [String] file
    # @param [String] password
    # @return [Fixnum] bytes written
    def self.to_pem_file(jwk, file, password = nil)
      return from(jwk).to_pem_file(file, password)
    end

    # Calls {JOSE::JWK#to_pem JOSE::JWK#to_pem} on a {JOSE::JWK JOSE::JWK} and then writes the binary to `file`.
    #
    # @param [String] file
    # @param [String] password
    # @return [Fixnum] bytes written
    def to_pem_file(file, password = nil)
      return File.binwrite(file, to_pem(password))
    end

    # Converts a private {JOSE::JWK JOSE::JWK} into a public {JOSE::JWK JOSE::JWK}.
    #
    #     !!!ruby
    #     jwk_rsa = JOSE::JWK.generate_key([:rsa, 1024]).to_map
    #     # => JOSE::Map[
    #     #  "dq" => "Iv_BghpjRyv8hk4AgsX_3w",
    #     #  "e" => "AQAB",
    #     #  "d" => "imiCh2gK77pDAa_NuQbHN1hZdLY0eTl8tp4WLfe1uQ0",
    #     #  "p" => "-eKE_wk7O5JWw_1fw-rciw",
    #     #  "qi" => "MqCwIoTTCkYmGQHsOM7IuA",
    #     #  "n" => "vj2WbxlGF1yU9SoQJMqKw6c2asTks_cVuXEAO3x_yOU",
    #     #  "kty" => "RSA",
    #     #  "q" => "wuVog_0-60w7_56y8wZuTw",
    #     #  "dp" => "lU_9GEdz1UzD-6hSqMaVsQ"]
    #     JOSE::JWK.to_public(jwk_rsa).to_map
    #     # => JOSE::Map[
    #     #  "e" => "AQAB",
    #     #  "n" => "vj2WbxlGF1yU9SoQJMqKw6c2asTks_cVuXEAO3x_yOU",
    #     #  "kty" => "RSA"]
    #
    # @param [JOSE::Map, Hash, String, JOSE::JWK, Array<JOSE::Map, Hash, String, JOSE::JWK>] jwk
    # @return [JOSE::JWK, Array<JOSE::JWK>]
    def self.to_public(jwk)
      if jwk.is_a?(Array)
        return from(jwk).map { |obj| obj.to_public }
      else
        return from(jwk).to_public
      end
    end

    # Converts a private {JOSE::JWK JOSE::JWK} into a public {JOSE::JWK JOSE::JWK}.
    #
    # @see JOSE::JWK.to_public
    # @return [JOSE::JWK]
    def to_public
      return JOSE::JWK.from_map(to_public_map)
    end

    # Calls {JOSE::JWK.to_binary JOSE::JWK.to_binary} on a {JOSE::JWK JOSE::JWK} and then writes the binary to `file`.
    #
    # @param [JOSE::Map, Hash, String, JOSE::JWK] jwk
    # @param [String] file
    # @return [Fixnum] bytes written
    def self.to_public_file(jwk, file)
      return from(jwk).to_public_file(file)
    end

    # Calls {JOSE::JWK.to_public JOSE::JWK.to_public} on a {JOSE::JWK JOSE::JWK} and then writes the binary to `file`.
    #
    # @param [String] file
    # @return [Fixnum] bytes written
    def to_public_file(file)
      return File.binwrite(file, to_public.to_binary)
    end

    # Calls {JOSE::JWK.to_public JOSE::JWK.to_public} and then {JOSE::JWK.to_key JOSE::JWK.to_key} on a {JOSE::JWK JOSE::JWK}.
    #
    # @param [JOSE::Map, Hash, String, JOSE::JWK, Array<JOSE::Map, Hash, String, JOSE::JWK>] jwk
    # @return [OpenSSL::PKey, Object, Array<OpenSSL::PKey, Object>]
    def self.to_public_key(jwk)
      if jwk.is_a?(Array)
        return from(jwk).map { |obj| obj.to_public_key }
      else
        return from(jwk).to_public_key
      end
    end

    # Calls {JOSE::JWK#to_public JOSE::JWK#to_public} and then {JOSE::JWK#to_key JOSE::JWK#to_key} on a {JOSE::JWK JOSE::JWK}.
    #
    # @return [OpenSSL::PKey, Object]
    def to_public_key
      return to_public.to_key
    end

    # Calls {JOSE::JWK.to_public JOSE::JWK.to_public} and then {JOSE::JWK.to_map JOSE::JWK.to_map} on a {JOSE::JWK JOSE::JWK}.
    #
    # @param [JOSE::Map, Hash, String, JOSE::JWK, Array<JOSE::Map, Hash, String, JOSE::JWK>] jwk
    # @return [JOSE::Map, Array<JOSE::Map>]
    def self.to_public_map(jwk)
      if jwk.is_a?(Array)
        return from(jwk).map { |obj| obj.to_public_map }
      else
        return from(jwk).to_public_map
      end
    end

    # Calls {JOSE::JWK#to_public JOSE::JWK#to_public} and then {JOSE::JWK#to_map JOSE::JWK#to_map} on a {JOSE::JWK JOSE::JWK}.
    #
    # @return [JOSE::Map]
    def to_public_map
      return kty.to_public_map(fields)
    end

    # Converts a {JOSE::JWK JOSE::JWK} into a map that can be used by {JOSE::JWK.thumbprint JOSE::JWK.thumbprint}.
    #
    # @param [JOSE::Map, Hash, String, JOSE::JWK, Array<JOSE::Map, Hash, String, JOSE::JWK>] jwk
    # @return [JOSE::Map, Array<JOSE::Map>]
    def self.to_thumbprint_map(jwk)
      if jwk.is_a?(Array)
        return from(jwk).map { |obj| obj.to_thumbprint_map }
      else
        return from(jwk).to_thumbprint_map
      end
    end

    # Converts a {JOSE::JWK JOSE::JWK} into a map that can be used by {JOSE::JWK.thumbprint JOSE::JWK.thumbprint}.
    #
    # @return [JOSE::Map]
    def to_thumbprint_map
      return kty.to_thumbprint_map(fields)
    end

    # API

    # Decrypts the `encrypted` binary or map using the `jwk`.
    #
    # @see JOWE::JWE.block_decrypt
    # @param [JOSE::JWK] jwk
    # @param [JOSE::EncryptedBinary, JOSE::EncryptedMap] encrypted
    # @return [[String, JOSE::JWE]]
    def self.block_decrypt(jwk, encrypted)
      if jwk.is_a?(Array)
        public_jwk, secret_jwk = from(jwk)
        if secret_jwk.nil?
          secret_jwk = public_jwk
          public_jwk = nil
        end
        return box_decrypt(secret_jwk, encrypted, public_jwk)
      else
        return from(jwk).block_decrypt(encrypted)
      end
    end

    # Decrypts the `encrypted` binary or map using the `jwk`.
    #
    # @see JOWE::JWE.block_decrypt
    # @param [JOSE::EncryptedBinary, JOSE::EncryptedMap] encrypted
    # @return [[String, JOSE::JWE]]
    def block_decrypt(encrypted)
      return JOSE::JWE.block_decrypt(self, encrypted)
    end

    # Encrypts the `plain_text` using the `jwk` and algorithms specified by the `jwe`.
    #
    # @see JOSE::JWE.block_encrypt
    # @param [JOSE::JWK] jwk
    # @param [String] plain_text
    # @param [JOSE::JWE] jwe
    # @return [JOSE::EncryptedMap]
    def self.block_encrypt(jwk, plain_text, jwe = nil)
      if jwk.is_a?(Array)
        return box_encrypt(plain_text, from(jwk), jwe)
      else
        return from(jwk).block_encrypt(plain_text, jwe)
      end
    end

    # Encrypts the `plain_text` using the `jwk` and algorithms specified by the `jwe`.
    #
    # @see JOSE::JWE.block_encrypt
    # @param [String] plain_text
    # @param [JOSE::JWE] jwe
    # @return [JOSE::EncryptedMap]
    def block_encrypt(plain_text, jwe = nil)
      jwe ||= block_encryptor
      return JOSE::JWE.block_encrypt(self, plain_text, jwe)
    end

    # Returns a block encryptor map for the key type.
    #
    # @param [JOSE::JWK, Array<JOSE::JWK>] jwk
    # @return [JOSE::Map, Array<JOSE::Map>]
    def self.block_encryptor(jwk)
      if jwk.is_a?(Array)
        return from(jwk).map { |obj| obj.block_encryptor }
      else
        return from(jwk).block_encryptor
      end
    end

    # Returns a block encryptor map for the key type.
    #
    # @return [JOSE::Map]
    def block_encryptor
      return kty.block_encryptor(fields)
    end

    # Key Agreement decryption of the `encrypted` binary or map using `my_private_jwk`.
    #
    # @see JOSE::JWK.box_encrypt
    # @see JOSE::JWE.block_decrypt
    # @param [JOSE::JWK] jwk
    # @param [JOSE::EncryptedBinary, JOSE::EncryptedMap] encrypted
    # @param [JOSE::JWK] public_jwk
    # @return [[String, JOSE::JWE]]
    def self.box_decrypt(jwk, encrypted, public_jwk = nil)
      return from(jwk).box_decrypt(encrypted, public_jwk)
    end

    # Key Agreement decryption of the `encrypted` binary or map using `my_private_jwk`.
    #
    # @see JOSE::JWK.box_encrypt
    # @see JOSE::JWE.block_decrypt
    # @param [JOSE::EncryptedBinary, JOSE::EncryptedMap] encrypted
    # @param [JOSE::JWK] public_jwk
    # @return [[String, JOSE::JWE]]
    def box_decrypt(encrypted, public_jwk = nil)
      if public_jwk
        return JOSE::JWE.block_decrypt([public_jwk, self], encrypted)
      else
        return JOSE::JWE.block_decrypt(self, encrypted)
      end
    end

    # Key Agreement encryption of `plain_text` by generating an ephemeral private key based on `other_public_jwk` curve.
    #
    # If no private key has been specified in `box_keys`, it generates an ephemeral private key based on other public key curve.
    #
    # @see JOSE::JWK.box_decrypt
    # @see JOSE::JWE.block_encrypt
    # @param [String] plain_text
    # @param [JOSE::JWK, [JOSE::JWK, JOSE::JWK]] box_keys
    # @param [JOSE::JWE] jwe
    # @return [JOSE::EncryptedMap, [JOSE::EncryptedMap, JOSE::JWK]]
    def self.box_encrypt(plain_text, box_keys, jwe = nil)
      jwk_public, jwk_secret = from(box_keys)
      return jwk_public.box_encrypt(plain_text, jwk_secret, jwe)
    end

    # Key Agreement encryption of `plain_text` by generating an ephemeral private key based on `other_public_jwk` curve.
    #
    # If no private key has been specified in `my_private_key`, it generates an ephemeral private key based on other public key curve.
    #
    # @see JOSE::JWK.box_decrypt
    # @see JOSE::JWE.block_encrypt
    # @param [String] plain_text
    # @param [JOSE::JWK] jwk_secret
    # @param [JOSE::JWE] jwe
    # @return [JOSE::EncryptedMap, [JOSE::EncryptedMap, JOSE::JWK]]
    def box_encrypt(plain_text, jwk_secret = nil, jwe = nil)
      epk_secret = nil
      jwk_public = self
      if jwk_secret.nil?
        epk_secret = jwk_secret = jwk_public.generate_key
      end
      if not jwk_secret.is_a?(JOSE::JWK)
        jwk_secret = JOSE::JWK.from(jwk_secret)
      end
      if jwe.nil?
        jwe = jwk_public.block_encryptor
      end
      if jwe.is_a?(Hash)
        jwe = JOSE::Map.new(jwe)
      end
      if jwe.is_a?(JOSE::Map)
        if jwe['apu'].nil?
          jwe = jwe.put('apu', jwk_secret.fields['kid'] || jwk_secret.thumbprint)
        end
        if jwe['apv'].nil?
          jwe = jwe.put('apv', jwk_public.fields['kid'] || jwk_public.thumbprint)
        end
        if jwe['epk'].nil?
          jwe = jwe.put('epk', jwk_secret.to_public_map)
        end
      end
      if epk_secret
        return JOSE::JWE.block_encrypt([jwk_public, jwk_secret], plain_text, jwe), epk_secret
      else
        return JOSE::JWE.block_encrypt([jwk_public, jwk_secret], plain_text, jwe)
      end
    end

    # Derives a key (typically just returns a binary representation of the key).
    #
    # @param [JOSE::JWK] jwk
    # @param [*Object] args
    # @return [String]
    def self.derive_key(jwk, *args)
      return from(jwk).derive_key(*args)
    end

    # Derives a key (typically just returns a binary representation of the key).
    #
    # @param [*Object] args
    # @return [String]
    def derive_key(*args)
      return kty.derive_key(*args)
    end

    # Generates a new {JOSE::JWK JOSE::JWK} based on another {JOSE::JWK JOSE::JWK} or from initialization params provided.
    #
    # Passing another {JOSE::JWK JOSE::JWK} results in different behavior depending on the `"kty"`:
    #
    #   * `"EC"` - uses the same named curve to generate a new key
    #   * `"oct"` - uses the byte size to generate a new key
    #   * `"OKP"` - uses the named curve to generate a new key
    #   * `"RSA"` - uses the same modulus and exponent sizes to generate a new key
    #
    # The following initialization params may also be used:
    #
    #   * `[:ec, "P-256" | "P-384" | "P-521"]` - generates an `"EC"` key using the `"P-256"`, `"P-384"`, or `"P-521"` curves
    #   * `[:oct, bytes]` - generates an `"oct"` key made of a random `bytes` number of bytes
    #   * `[:okp, :Ed25519 | :Ed25519ph | :Ed448 | :Ed448ph | :X25519 | :X448]` - generates an `"OKP"` key using the specified curve
    #   * `[:rsa, modulus_size] | [:rsa, modulus_size, exponent_size]` - generates an `"RSA"` key using the `modulus_size` and `exponent_size`
    #
    # @param [Array] params
    # @return [JOSE::JWK]
    def self.generate_key(params)
      if params.is_a?(Array) and (params.length == 2 or params.length == 3)
        case params[0]
        when :ec
          return JOSE::JWK.new(nil, *JOSE::JWK::KTY_EC.generate_key(params))
        when :oct
          return JOSE::JWK.new(nil, *JOSE::JWK::KTY_oct.generate_key(params))
        when :okp
          case params[1]
          when :Ed25519
            return JOSE::JWK.new(nil, *JOSE::JWK::KTY_OKP_Ed25519.generate_key(params))
          when :Ed25519ph
            return JOSE::JWK.new(nil, *JOSE::JWK::KTY_OKP_Ed25519ph.generate_key(params))
          when :Ed448
            return JOSE::JWK.new(nil, *JOSE::JWK::KTY_OKP_Ed448.generate_key(params))
          when :Ed448ph
            return JOSE::JWK.new(nil, *JOSE::JWK::KTY_OKP_Ed448ph.generate_key(params))
          when :X25519
            return JOSE::JWK.new(nil, *JOSE::JWK::KTY_OKP_X25519.generate_key(params))
          when :X448
            return JOSE::JWK.new(nil, *JOSE::JWK::KTY_OKP_X448.generate_key(params))
          else
            raise ArgumentError, "invalid :okp key generation params"
          end
        when :rsa
          return JOSE::JWK.new(nil, *JOSE::JWK::KTY_RSA.generate_key(params))
        else
          raise ArgumentError, "invalid key generation params"
        end
      elsif params.is_a?(JOSE::JWK)
        return params.generate_key
      elsif params.respond_to?(:generate_key)
        return JOSE::JWK.new(nil, *params.generate_key(JOSE::Map[]))
      else
        raise ArgumentError, "invalid key generation params"
      end
    end

    # Generates a new key based on the current one.
    #
    # @return [JOSE::JWK]
    def generate_key
      return JOSE::JWK.new(nil, *kty.generate_key(fields))
    end

    # Merges map on right into map on left.
    # @param [JOSE::Map, Hash, String, JOSE::JWK] left
    # @param [JOSE::Map, Hash, String, JOSE::JWK] right
    # @return [JOSE::JWK]
    def self.merge(left, right)
      return from(left).merge(right)
    end

    # Merges object into current map.
    # @param [JOSE::Map, Hash, String, JOSE::JWK] object
    # @return [JOSE::JWK]
    def merge(object)
      object = case object
      when JOSE::Map, Hash
        object
      when String
        JOSE.decode(object)
      when JOSE::JWK
        object.to_map
      else
        raise ArgumentError, "'object' must be a Hash, String, or JOSE::JWK"
      end
      return JOSE::JWK.from_map(self.to_map.merge(object))
    end

    # Computes the shared secret between two keys.
    #
    # Currently only works for `"EC"` keys and `"OKP"` keys with `"crv"` set to `"X25519"` or `"X448"`.
    #
    # @param [JOSE::JWK] your_jwk
    # @param [JOSE::JWK] my_jwk
    # @return [String]
    def self.shared_secret(your_jwk, my_jwk)
      return from(your_jwk).shared_secret(from(my_jwk))
    end

    # Computes the shared secret between two keys.
    #
    # Currently only works for `"EC"` keys and `"OKP"` keys with `"crv"` set to `"X25519"` or `"X448"`.
    #
    # @param [JOSE::JWK] other_jwk
    # @return [String]
    def shared_secret(other_jwk)
      other_jwk = from(other_jwk) if not other_jwk.is_a?(JOSE::JWK)
      raise ArgumentError, "key types must match" if other_jwk.kty.class != kty.class
      raise ArgumentError, "key type does not support shared secret computations" if not kty.respond_to?(:derive_key)
      return kty.derive_key(other_jwk)
    end

    # Signs the `plain_text` using the `jwk` and the default signer algorithm `jws` for the key type.
    #
    # @see JOSE::JWS.sign
    # @param [String] plain_text
    # @param [JOSE::JWS] jws
    # @param [JOSE::JWK] jwk
    # @param [JOSE::Map] header
    # @return [JOSE::SignedMap]
    def self.sign(plain_text, jws, jwk = nil, header = nil)
      if jwk.nil?
        jwk = jws
        jws = nil
      end
      return from(jwk).sign(plain_text, jws, header)
    end

    # Signs the `plain_text` using the `jwk` and the default signer algorithm `jws` for the key type.
    #
    # @see JOSE::JWS.sign
    # @param [String] plain_text
    # @param [JOSE::JWS] jws
    # @param [JOSE::Map] header
    # @return [JOSE::SignedMap]
    def sign(plain_text, jws = nil, header = nil)
      jws ||= signer
      return JOSE::JWS.sign(self, plain_text, jws, header)
    end

    # Returns a signer map for the key type.
    #
    # @param [JOSE::JWK] jwk
    # @return [JOSE::Map]
    def self.signer(jwk)
      return from(jwk).signer
    end

    # Returns a signer map for the key type.
    #
    # @return [JOSE::Map]
    def signer
      return kty.signer(fields)
    end

    # Returns the unique thumbprint for a {JOSE::JWK JOSE::JWK} using the `digest_type`.
    #
    #     !!!ruby
    #     # let's define two different keys that will have the same thumbprint
    #     jwk1 = JOSE::JWK.from_oct("secret")
    #     jwk2 = JOSE::JWK.from({ "use" => "sig", "k" => "c2VjcmV0", "kty" => "oct" })
    #
    #     JOSE::JWK.thumbprint(jwk1)
    #     # => "DWBh0SEIAPYh1x5uvot4z3AhaikHkxNJa3Ada2fT-Cg"
    #     JOSE::JWK.thumbprint(jwk2)
    #     # => "DWBh0SEIAPYh1x5uvot4z3AhaikHkxNJa3Ada2fT-Cg"
    #     JOSE::JWK.thumbprint('MD5', jwk1)
    #     # => "Kldz8k5PQm7y1E3aNBlMiA"
    #     JOSE::JWK.thumbprint('MD5', jwk2)
    #     # => "Kldz8k5PQm7y1E3aNBlMiA"
    #
    # @see https://tools.ietf.org/html/rfc7638 RFC 7638 - JSON Web Key (JWK) Thumbprint
    # @param [String] digest_type
    # @param [JOSE::JWK] jwk
    # @return [String]
    def self.thumbprint(digest_type, jwk = nil)
      if jwk.nil?
        jwk = digest_type
        digest_type = nil
      end
      return from(jwk).thumbprint(digest_type)
    end

    # Returns the unique thumbprint for a {JOSE::JWK JOSE::JWK} using the `digest_type`.
    #
    # @see JOSE::JWK.thumbprint
    # @see https://tools.ietf.org/html/rfc7638 RFC 7638 - JSON Web Key (JWK) Thumbprint
    # @param [String] digest_type
    # @return [String]
    def thumbprint(digest_type = nil)
      digest_type ||= 'SHA256'
      thumbprint_binary = JOSE.encode(to_thumbprint_map)
      return JOSE.urlsafe_encode64(OpenSSL::Digest.new(digest_type).digest(thumbprint_binary))
    end

    # Returns a verifier algorithm list for the key type.
    #
    # @param [JOSE::JWK] jwk
    # @return [Array<String>]
    def self.verifier(jwk)
      if jwk.is_a?(Array)
        return from(jwk).map { |obj| obj.verifier }
      else
        return from(jwk).verifier
      end
    end

    # Returns a verifier algorithm list for the key type.
    #
    # @return [Array<String>]
    def verifier
      return kty.verifier(fields)
    end

    # Verifies the `signed` using the `jwk`.
    #
    # @see JOSE::JWS.verify
    # @param [JOSE::SignedBinary, JOSE::SignedMap] signed
    # @param [JOSE::JWK] jwk
    # @return [[Boolean, String, JOSE::JWS]]
    def self.verify(signed, jwk)
      return from(jwk).verify(signed)
    end

    # Verifies the `signed` using the `jwk`.
    #
    # @see JOSE::JWS.verify
    # @param [JOSE::SignedBinary, JOSE::SignedMap] signed
    # @return [[Boolean, String, JOSE::JWS]]
    def verify(signed)
      return JOSE::JWS.verify(self, signed)
    end

    # Verifies the `signed` using the `jwk` and whitelists the `"alg"` using `allow`.
    #
    # @see JOSE::JWS.verify_strict
    # @param [JOSE::SignedBinary, JOSE::SignedMap] signed
    # @param [Array<String>] allow
    # @param [JOSE::JWK] jwk
    # @return [[Boolean, String, JOSE::JWS]]
    def self.verify_strict(signed, allow, jwk)
      return from(jwk).verify_strict(signed, allow)
    end

    # Verifies the `signed` using the `jwk` and whitelists the `"alg"` using `allow`.
    #
    # @see JOSE::JWS.verify_strict
    # @param [JOSE::SignedBinary, JOSE::SignedMap] signed
    # @param [Array<String>] allow
    # @return [[Boolean, String, JOSE::JWS]]
    def verify_strict(signed, allow)
      return JOSE::JWS.verify_strict(self, allow, signed)
    end

  private

    def self.from_fields(jwk, modules)
      if jwk.fields.has_key?('keys')
        keys = modules[:keys] || JOSE::JWK::Set
        jwk.keys, jwk.fields = keys.from_map(jwk.fields)
        return from_fields(jwk, modules)
      elsif jwk.fields.has_key?('kty')
        kty = modules[:kty] || case jwk.fields['kty']
        when 'EC'
          JOSE::JWK::KTY_EC
        when 'oct'
          JOSE::JWK::KTY_oct
        when 'OKP'
          case jwk.fields['crv']
          when 'Ed25519'
            JOSE::JWK::KTY_OKP_Ed25519
          when 'Ed25519ph'
            JOSE::JWK::KTY_OKP_Ed25519ph
          when 'Ed448'
            JOSE::JWK::KTY_OKP_Ed448
          when 'Ed448ph'
            JOSE::JWK::KTY_OKP_Ed448ph
          when 'X25519'
            JOSE::JWK::KTY_OKP_X25519
          when 'X448'
            JOSE::JWK::KTY_OKP_X448
          else
            raise ArgumentError, "unknown 'crv' for 'kty' of 'OKP': #{jwk.fields['crv'].inspect}"
          end
        when 'RSA'
          JOSE::JWK::KTY_RSA
        else
          raise ArgumentError, "unknown 'kty': #{jwk.fields['kty'].inspect}"
        end
        jwk.kty, jwk.fields = kty.from_map(jwk.fields)
        return from_fields(jwk, modules)
      elsif jwk.keys.nil? and jwk.kty.nil?
        raise ArgumentError, "missing required keys: 'keys' or 'kty'"
      else
        return jwk
      end
    end

  end
end

require 'jose/jwk/pem'
require 'jose/jwk/openssh_key'
require 'jose/jwk/set'
require 'jose/jwk/kty'
