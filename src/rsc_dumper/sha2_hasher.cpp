#include "sha2_hasher.h"
#include <memory>

#define TO_HASH_SIZE 0x10000
#define SHA512_DIGEST_SIZE (512 / 8)

using namespace std;

Botan::secure_vector<uint8_t> hash_buffer(const uint8_t * data, uint32_t data_len, bool sha256){
	unique_ptr<Botan::HashFunction> sha(Botan::HashFunction::create(sha256 ? "SHA-256" : "SHA-512"));
	sha->update(data, data_len);
	return sha->final();
}

Botan::secure_vector<uint8_t> hash_pwd(const char* pwd, const uint8_t* salt) {
	unique_ptr<Botan::HashFunction> sha(Botan::HashFunction::create("SHA-256"));
    uint32_t cur_size = 0;
    uint32_t password_len = strlen(pwd);
    while(cur_size < TO_HASH_SIZE){
        //add salt
        sha->update(salt, min((uint32_t)8, TO_HASH_SIZE - cur_size));
        cur_size += 8;
        if(cur_size >= TO_HASH_SIZE)
            break;
        //add password
        sha->update((uint8_t *)pwd, min(password_len, TO_HASH_SIZE - cur_size));
        cur_size += password_len;
    }
     return sha->final();
}

Botan::secure_vector<uint8_t> sha512_prng(const uint8_t * seed, uint32_t seed_len, uint32_t out_length){
	Botan::secure_vector<uint8_t> to_return;
	to_return.resize(out_length);

	Botan::secure_vector<uint8_t> tmp_hash = hash_buffer(seed, seed_len, false);

	uint32_t bytes_hashed = 0;

	while (bytes_hashed + SHA512_DIGEST_SIZE <= out_length) {
		Botan::secure_vector<uint8_t> to_output = hash_buffer(tmp_hash.data(), SHA512_DIGEST_SIZE, false);
		memcpy(to_return.data() + bytes_hashed, to_output.data(), SHA512_DIGEST_SIZE);

		//not really sure why can't BCVE just do a regular increment, but this is how it's implemented...
		int32_t cur_index = SHA512_DIGEST_SIZE - 1;
		uint8_t prev_value;
		do {
			prev_value = tmp_hash[cur_index];
			tmp_hash[cur_index]++;
			cur_index--;
		} while (cur_index >= 0 && !prev_value);

		bytes_hashed += SHA512_DIGEST_SIZE;
	}

	//handle cases when output size is not a multiple of SHA512_DIGEST_SIZE
	if (bytes_hashed < out_length) {
		uint32_t remaining = out_length - bytes_hashed;
		Botan::secure_vector<uint8_t> to_output = hash_buffer(tmp_hash.data(), SHA512_DIGEST_SIZE, false);
		memcpy(to_return.data() + bytes_hashed, to_output.data(), remaining);
	}

	return to_return;
}