require 'test_helper'

class JOSE::JWK::PEMTest < Minitest::Test

  def test_from_pem_and_to_pem
    ec_pem_data = \
      "-----BEGIN EC PRIVATE KEY-----\n" \
      "MHcCAQEEIFISMjkku2kVv9s4iHuyr0AJR8SVqGtv/4xXYuu1ae3woAoGCCqGSM49\n" \
      "AwEHoUQDQgAEDwZ8OJ8ZVGE8zhSXbsnL+1kJ+I6Sl92hBGTY7cTWS+ba3Mn3lwmY\n" \
      "7cnK6ZESgGXGDvO11wRXTd2qS31H4bIEDw==\n" \
      "-----END EC PRIVATE KEY-----\n"
    ec_pem_json = "{\"crv\":\"P-256\",\"d\":\"UhIyOSS7aRW_2ziIe7KvQAlHxJWoa2__jFdi67Vp7fA\",\"kty\":\"EC\",\"x\":\"DwZ8OJ8ZVGE8zhSXbsnL-1kJ-I6Sl92hBGTY7cTWS-Y\",\"y\":\"2tzJ95cJmO3JyumREoBlxg7ztdcEV03dqkt9R-GyBA8\"}"
    ec_pem = JOSE::JWK.from(ec_pem_json)
    assert_equal ec_pem, JOSE::JWK.from_pem(ec_pem_data)
    assert_equal ec_pem_data, JOSE::JWK.to_pem(ec_pem)
    ec_pem_password = SecureRandom.urlsafe_base64(16)
    encrypted_ec_pem_data = JOSE::JWK.to_pem(ec_pem, ec_pem_password)
    refute_equal ec_pem_data, encrypted_ec_pem_data
    assert_equal ec_pem, JOSE::JWK.from_pem(encrypted_ec_pem_data, ec_pem_password)
    rsa_pem_data = \
      "-----BEGIN RSA PRIVATE KEY-----\n" \
      "MIIEpAIBAAKCAQEAxnAUUvtW3ftv25jCB+hePVCnhROqH2PACVGoCybdtMYTl8qV\n" \
      "ABAR0d6T+BRzVhJzz0+UvBNFUQyVvKAFxtbQUZN2JgAm08UJrDQszqz5tTzodWex\n" \
      "ODdPuoCaWaWge/MZGhz5PwWd7Jc4bPAu0QzSVFpBP3CovSjv48Z2Eq0/LHXVjjX/\n" \
      "Az+WaUh94mXFyAxFI/oCygtT+il1+japS3cXJJh0WddT3VKEBRYHmxDJd/LYE+KX\n" \
      "Qt3aTDhq0vI9sG2ivtFj0dc3w/YBdr4hlcr42ujSP3wLTPpTjituwHQhYP4j+zqu\n" \
      "7J3FYaIxU4lkK9Y/DP27RxffFI9YDPJdwFkNJwIDAQABAoIBAANoByFJiTs0Rr5J\n" \
      "SANkvMFmsgl5xfDWAITobu8KEsI4qDtx0c73d6bXoEig6T3wASbs4cu8tPLoOWXM\n" \
      "hWzdYSQVWPDcDc6S0lCvcJl3pK20xvTE++jQIkE8Ven2CuQ1zxeAqdKoIQbfratJ\n" \
      "EDSseKvUBMy2/V6J5lxNmtdFPBFiSLPe9khRocSs3+mqukYu1AyutO54EMhIVZhs\n" \
      "a94AySwBkOcDmqeTWCC9rnyORWKh/km8v0JO9vfW/sOAdH5ervIrEfDpacDC1Zw/\n" \
      "qKjgTx/uubRPNocT1dEG0pss5oPYZVVYpyfNmEQZG3LvlxvV1zoVKiSe5Gn0K2JE\n" \
      "MegYhSkCgYEA5cMQg/4MrOnHI44xEs6Jyt/22DCvw3K+GY046Ls50vIf2KlRALHI\n" \
      "65SPKfVFo5hUuHkBuWnQV46tHJU0dlmfg4svPMm/581r59yXeI8W6G4FlsSiVyhF\n" \
      "O3P5Q5ubVs7MNaqhvaqqPqR14cVvHSqjwX5jGuGAVuLhnOhZGbtb7/UCgYEA3RlG\n" \
      "NrCRU+yV7TTikKJVJCIpe8vgLBkHQ61iuICd8AyHa4sXICgf2YBFgW8CAJOHKIp8\n" \
      "g/Nl94VYpqWvN1YVDB7sFUlRpJL2yXvTKxDzUwtM5pf/D1O6lGEMQBRY+buhZHmP\n" \
      "f5qG93LnsSqm5YOZGpZ6t6gHtYM9A6JOIgwsYysCgYBSx6DfrVxrwB6bVNOhbwB+\n" \
      "M4sAASqSRHjxQ8xJLYt70PhgW0Bv+53kIrYh69iXRH7hp9dTMih6I1GDhs5MBaZP\n" \
      "AoqWYCngHkbOVs/MA+HBBELHOzkyJbQr43DfRuUEtaUlgMCdUSvdPeuq2DNcUsyF\n" \
      "HkAeozhWFZArtBrGBpbtMQKBgQDK55b4ObIlQsmUlyQVd+SK9I79fWyNC6sPAN/I\n" \
      "UsCeu+DLYSon6KrSAFXJIwbDYKB5JB6BOa4qKcXhqcvTDLzkEry2DENQtU6mOWzh\n" \
      "6PxlCcnZFUSN3FkuMqH7bLD6/qZufuCiSj3yeREIFgx0NQEc1Vxpj1sDyR0FaL4r\n" \
      "oOBbYQKBgQCQblK162WzXz/V+9DHyvGFfYCKzReDSAsNSOkT/1Nhxv662rv0dUo5\n" \
      "D/Y8kbPT2FD+16qeFeGAYy5upqS2XpQ5ImvoHgmBwBjvJT7fgS5LGny4ouLH0FWw\n" \
      "XZymILgAOGMso/1zshDtfvN+zffr9F5vx+H0b/NF3AR+aoXLubbwuA==\n" \
      "-----END RSA PRIVATE KEY-----\n"
    rsa_pem_json = "{\"d\":\"A2gHIUmJOzRGvklIA2S8wWayCXnF8NYAhOhu7woSwjioO3HRzvd3ptegSKDpPfABJuzhy7y08ug5ZcyFbN1hJBVY8NwNzpLSUK9wmXekrbTG9MT76NAiQTxV6fYK5DXPF4Cp0qghBt-tq0kQNKx4q9QEzLb9XonmXE2a10U8EWJIs972SFGhxKzf6aq6Ri7UDK607ngQyEhVmGxr3gDJLAGQ5wOap5NYIL2ufI5FYqH-Sby_Qk7299b-w4B0fl6u8isR8OlpwMLVnD-oqOBPH-65tE82hxPV0QbSmyzmg9hlVVinJ82YRBkbcu-XG9XXOhUqJJ7kafQrYkQx6BiFKQ\",\"dp\":\"Useg361ca8Aem1TToW8AfjOLAAEqkkR48UPMSS2Le9D4YFtAb_ud5CK2IevYl0R-4afXUzIoeiNRg4bOTAWmTwKKlmAp4B5GzlbPzAPhwQRCxzs5MiW0K-Nw30blBLWlJYDAnVEr3T3rqtgzXFLMhR5AHqM4VhWQK7QaxgaW7TE\",\"dq\":\"yueW-DmyJULJlJckFXfkivSO_X1sjQurDwDfyFLAnrvgy2EqJ-iq0gBVySMGw2CgeSQegTmuKinF4anL0wy85BK8tgxDULVOpjls4ej8ZQnJ2RVEjdxZLjKh-2yw-v6mbn7goko98nkRCBYMdDUBHNVcaY9bA8kdBWi-K6DgW2E\",\"e\":\"AQAB\",\"kty\":\"RSA\",\"n\":\"xnAUUvtW3ftv25jCB-hePVCnhROqH2PACVGoCybdtMYTl8qVABAR0d6T-BRzVhJzz0-UvBNFUQyVvKAFxtbQUZN2JgAm08UJrDQszqz5tTzodWexODdPuoCaWaWge_MZGhz5PwWd7Jc4bPAu0QzSVFpBP3CovSjv48Z2Eq0_LHXVjjX_Az-WaUh94mXFyAxFI_oCygtT-il1-japS3cXJJh0WddT3VKEBRYHmxDJd_LYE-KXQt3aTDhq0vI9sG2ivtFj0dc3w_YBdr4hlcr42ujSP3wLTPpTjituwHQhYP4j-zqu7J3FYaIxU4lkK9Y_DP27RxffFI9YDPJdwFkNJw\",\"p\":\"5cMQg_4MrOnHI44xEs6Jyt_22DCvw3K-GY046Ls50vIf2KlRALHI65SPKfVFo5hUuHkBuWnQV46tHJU0dlmfg4svPMm_581r59yXeI8W6G4FlsSiVyhFO3P5Q5ubVs7MNaqhvaqqPqR14cVvHSqjwX5jGuGAVuLhnOhZGbtb7_U\",\"q\":\"3RlGNrCRU-yV7TTikKJVJCIpe8vgLBkHQ61iuICd8AyHa4sXICgf2YBFgW8CAJOHKIp8g_Nl94VYpqWvN1YVDB7sFUlRpJL2yXvTKxDzUwtM5pf_D1O6lGEMQBRY-buhZHmPf5qG93LnsSqm5YOZGpZ6t6gHtYM9A6JOIgwsYys\",\"qi\":\"kG5Stetls18_1fvQx8rxhX2Ais0Xg0gLDUjpE_9TYcb-utq79HVKOQ_2PJGz09hQ_teqnhXhgGMubqaktl6UOSJr6B4JgcAY7yU-34EuSxp8uKLix9BVsF2cpiC4ADhjLKP9c7IQ7X7zfs336_Reb8fh9G_zRdwEfmqFy7m28Lg\"}"
    rsa_pem = JOSE::JWK.from(rsa_pem_json)
    assert_equal rsa_pem, JOSE::JWK.from_pem(rsa_pem_data)
    assert_equal rsa_pem_data, JOSE::JWK.to_pem(rsa_pem)
    rsa_pem_password = SecureRandom.urlsafe_base64(16)
    encrypted_rsa_pem_data = JOSE::JWK.to_pem(rsa_pem, rsa_pem_password)
    refute_equal rsa_pem_data, encrypted_rsa_pem_data
    assert_equal rsa_pem, JOSE::JWK.from_pem(encrypted_rsa_pem_data, rsa_pem_password)
  end

end
