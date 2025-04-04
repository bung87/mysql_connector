import openssl

func rsa_publickey_encrypt*(password_orig, seed, pubkey_pem: string): string =
  var password = password_orig
  password.add(chr(0x00))
  var bio = bioNew(bioSMem())

  discard BIO_write(bio, pubkey_pem.cstring, pubkey_pem.len.cint)

  var rsa = PEM_read_bio_RSA_PUBKEY(bio, nil, nil, nil)
  discard BIO_free(bio)

  var rsa_size = RSA_size(rsa)

  var input = newString(password.len)
  for i in 0..<password.len:
    input[i] = (password[i].uint8 xor seed[i mod seed.len].uint8).chr()
  result = newString(rsa_size)

  when (NimMajor, NimMinor) >= (2, 0):
    var fr = cast[ptr uint8](input[0].addr)
    var to = cast[ptr uint8](result[0].addr)
  else:
    var fr = cast[ptr cuchar](input[0].addr)
    var to = cast[ptr cuchar](result[0].addr)

  discard RSA_public_encrypt(input.len.cint, fr, to, rsa, RSA_PKCS1_OAEP_PADDING )
  RSA_free(rsa)

  return result