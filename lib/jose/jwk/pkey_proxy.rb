require 'delegate'

class JOSE::JWK::PKeyProxy < SimpleDelegator
  def ==(other)
    __getobj__.export == other.export
  end
end
