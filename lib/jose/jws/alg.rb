module JOSE::JWS::ALG

  # Generates a new {JOSE::JWK JOSE::JWK} based on the `parameters` and `algorithm`.
  #
  # @see JOSE::JWK.generate_key
  # @param [Array] parameters
  # @param [String] algorithm
  # @return [JOSE::JWK]
  def self.generate_key(parameters, algorithm)
    return JOSE::JWK.generate_key(parameters).merge({
      'alg' => algorithm,
      'use' => 'sig'
    })
  end

end

require 'jose/jws/alg_ecdsa'
require 'jose/jws/alg_eddsa'
require 'jose/jws/alg_hmac'
require 'jose/jws/alg_none'
require 'jose/jws/alg_rsa_pkcs1_v1_5'
require 'jose/jws/alg_rsa_pss'
