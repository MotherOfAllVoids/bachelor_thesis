#pragma once
#include <cstdint>
#include <botan/block_cipher.h>
#include <botan/cipher_mode.h>


//decrypts a key_and_hash structure using a block cipher in CBC mode, make sure to always call it with a supported block_cipher id
void decrypt_key_and_hash(Botan::secure_vector<uint8_t>& key_and_hash, const Botan::secure_vector<uint8_t>& key, uint8_t block_cipher);

extern const std::string block_cipher_enum[];
