module JOSE::JWE::ALG

  # Generates a new {JOSE::JWK JOSE::JWK} based on the `parameters`, `algorithm`, and `encryption`.
  #
  # @see JOSE::JWK.generate_key
  # @param [Array] parameters
  # @param [String] algorithm
  # @param [String] encryption
  # @return [JOSE::JWK]
  def self.generate_key(parameters, algorithm, encryption)
    return JOSE::JWK.generate_key(parameters).merge({
      'alg' => algorithm,
      'enc' => encryption,
      'use' => 'enc'
    })
  end

end

require 'jose/jwe/alg_aes_gcm_kw'
require 'jose/jwe/alg_aes_kw'
require 'jose/jwe/alg_c20p_kw'
require 'jose/jwe/alg_dir'
require 'jose/jwe/alg_ecdh_es'
require 'jose/jwe/alg_pbes2'
require 'jose/jwe/alg_rsa'
require 'jose/jwe/alg_xc20p_kw'
