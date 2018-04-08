#pragma once

#include <cstdint>
#include <botan/hash.h>
#include <botan/cipher_mode.h>

//hash a password given a salt and return a secondary key
Botan::secure_vector<uint8_t> hash_pwd(const char* pwd, const uint8_t* salt);

//hash an arbitrary buffer using either sha256 or sha512
Botan::secure_vector<uint8_t> hash_buffer(const uint8_t * data, uint32_t data_len, bool sha256);

//emulate prng used in BCVE
Botan::secure_vector<uint8_t> sha512_prng(const uint8_t * seed,  uint32_t seed_len, uint32_t out_length);
