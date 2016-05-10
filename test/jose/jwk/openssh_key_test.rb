require 'test_helper'

class JOSE::JWK::OpenSSHKeyTest < Minitest::Test

  def test_from_openssh_key_and_to_openssh_key
    openssh_key_data = \
      "-----BEGIN OPENSSH PRIVATE KEY-----\n" \
      "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n" \
      "QyNTUxOQAAACDFTYYUG++LkJLGusZ3yx73nu+pHmpYejdMF+xapI6izwAAAJjGjSl9xo0p\n" \
      "fQAAAAtzc2gtZWQyNTUxOQAAACDFTYYUG++LkJLGusZ3yx73nu+pHmpYejdMF+xapI6izw\n" \
      "AAAEAyemtTz+pnC+cRZUYtwo1A4QEKCYewNwfFonL4ec52pcVNhhQb74uQksa6xnfLHvee\n" \
      "76kealh6N0wX7FqkjqLPAAAADnRlc3RAcnVieS1qb3NlAQIDBAUGBw==\n" \
      "-----END OPENSSH PRIVATE KEY-----\n"
    openssh_key_json = "{\"crv\":\"Ed25519\",\"d\":\"MnprU8_qZwvnEWVGLcKNQOEBCgmHsDcHxaJy-HnOdqU\",\"kid\":\"test@ruby-jose\",\"kty\":\"OKP\",\"x\":\"xU2GFBvvi5CSxrrGd8se957vqR5qWHo3TBfsWqSOos8\"}"
    openssh_key = JOSE::JWK.from(openssh_key_json)
    assert_equal openssh_key, JOSE::JWK.from_openssh_key(openssh_key_data)
    assert_equal openssh_key, JOSE::JWK.from_openssh_key(JOSE::JWK.to_openssh_key(openssh_key))
  end

end
