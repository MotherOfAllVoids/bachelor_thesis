#include "decryptor.h"
#include <memory>

using namespace std;

const string block_cipher_enum[] = { "", "AES", "Twofish", "Blowfish", "CAST-128", "GOST 28147-89", "Serpent", "RC6", "AES-256", "Twofish", "Serpent", "RC6" };

void decrypt_key_and_hash(Botan::secure_vector<uint8_t>& key_and_hash, const Botan::secure_vector<uint8_t>& key, uint8_t block_cipher) {
	unique_ptr<Botan::Cipher_Mode> enc(Botan::get_cipher_mode( block_cipher_enum[block_cipher] + "/CBC/NoPadding", Botan::DECRYPTION));
    enc->set_key(key);
    //set iv (full of zero bytes)
    vector<uint8_t> iv(enc->default_nonce_length());
    memset(iv.data(), 0, enc->default_nonce_length());
    enc->start(iv);
    //actually decrypt the KEY_AND_HASH
    enc->finish(key_and_hash);
}

