module JOSE::JWS::ALG

  extend self

end

require 'jose/jws/alg_ecdsa'
require 'jose/jws/alg_eddsa'
require 'jose/jws/alg_hmac'
require 'jose/jws/alg_rsa_pkcs1_v1_5'
require 'jose/jws/alg_rsa_pss'
