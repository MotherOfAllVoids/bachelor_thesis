#define __STDC_WANT_LIB_EXT1__ 1
#include "bcve_rsc_parser.h"
#include <iostream>
#include <fstream>
#include <unistd.h>
#include <algorithm>
#include <memory>

#define RECOVERY_STRUCT_SIZE 0xCF4
#define SHA_INPUT_SIZE 0x10000
#define SALT_SIZE 0x10000

using namespace std;


uint8_t RECOVERY_STRUCT_MAGIC[16] = {0x74, 0x0e, 0x0d, 0x8d, 0xe7, 0x5b, 0x13, 0x57, 0xf8, 0x72, 0x16, 0x71, 0xaf, 0x53, 0x7d, 0x5d};

//offsets of all the KEY_AND_HASH structures
uint32_t key_struct_offsets[] = {0x828, 0x888, 0xB14, 0xB78, 0xBDC, 0xC40};

//note that the id of AES is 8, Twofish 9 etc.
string cipher_enum[] = {"AES-256", "Twofish", "Serpent"};

//decrypts KEY_AND_HASH structure inplace in encrypted_buffer and returns if hash matches
bool decrypt_key_and_hash(Botan::secure_vector<uint8_t>& encrypted_buffer, const Botan::secure_vector<uint8_t>& secondary_key, uint8_t encryption_type){
    unique_ptr<Botan::Cipher_Mode> enc(Botan::get_cipher_mode( cipher_enum[encryption_type - 8] + "/CBC/NoPadding", Botan::DECRYPTION));
    enc->set_key(secondary_key);
    //set iv (full of zero bytes)
    vector<uint8_t> iv(enc->default_nonce_length());
    memset(iv.data(), 0, enc->default_nonce_length());
    enc->start(iv);
    //actually decrypt the KEY_AND_HASH
    enc->finish(encrypted_buffer);
    //now verify the hash
    unique_ptr<Botan::HashFunction> sha(Botan::HashFunction::create("SHA-256"));
    sha->update(encrypted_buffer.data(), 0x40);
    return !memcmp(sha->final().data(), encrypted_buffer.data() + 0x40, 0x20);
}

bool parse_rescue_file(const char* rsc_file_name, uint64_t recstruct_index, Botan::secure_vector<uint8_t>& enc_keys, vector<uint8_t>& encrypted_boot_sector, uint8_t& encryption_type){

    ifstream rscf(rsc_file_name, ios::in | ios::binary | ios::ate);
    if (!rscf.is_open()) {
        cerr<< "[error]: Can't open " << rsc_file_name << endl;
        return false;
    }

    //get size of rsc file and verify that it is a multiple of RECOVERY_STRUCT_SIZE
    uint32_t rscf_size = rscf.tellg();
    if (rscf_size % RECOVERY_STRUCT_SIZE) {
    	rscf_size -= rscf_size % RECOVERY_STRUCT_SIZE;
        cerr << "[warning]: Corrupt rsc file." << endl;
    }

    if(rscf_size == 0){
    	cerr << "[error]: Unable to get any information from this corrupt rsc file." << endl;
    	rscf.close();
        return false;
    }

    rscf.seekg(0, ios::beg);

    vector<uint8_t> rsc_file_mapped;
    rsc_file_mapped.resize(rscf_size);

    rscf.read((char *)rsc_file_mapped.data(), rscf_size);
    if (!rscf){
        cerr << "[error]: Error reading rsc file." << endl;
        rscf.close();
        return false;
    }

    //the number of RECOVERY_STRUCTS, whose KEY_STRUCTS can be decrypted with the given password
    uint32_t matching_structs = 0;
    uint32_t last_matching_struct = 0;
    char* password = getpass("Enter a BCVE password: ");
    uint32_t password_len = strlen(password);

    for(uint32_t i = 0; i < rscf_size / RECOVERY_STRUCT_SIZE; i++){
        if(recstruct_index != UINT64_MAX && recstruct_index != i)
            continue; //the user chose a specific RECOVERY_STRUCT, skip all others
        uint8_t * cur_rec_struct = rsc_file_mapped.data() + i * RECOVERY_STRUCT_SIZE;
        //skip if the RECOVERY_STRUCT signature is invalid or RECOVERY_STRUCT is freed
        if(memcmp(cur_rec_struct, RECOVERY_STRUCT_MAGIC, 16) || *(uint32_t *)(cur_rec_struct + 0x414) != 0)
            continue;
        uint8_t cur_encryption_type = cur_rec_struct[0x8e9];
        //LRW encryption mode and RC6 is not supported
        if(cur_encryption_type < 8 || cur_encryption_type > 10) {
            cerr << "[warning]: An unsupported block cipher with ID=" << (int)cur_encryption_type << " encountered in RECOVERY_STRUCT index=" << i << "." << endl;
            continue;
        }
        //either doesnt use XTS or uses LBAs as tweaks. Is in any case unsupported
        if(cur_rec_struct[0x8e8] != 0x18){
            cerr << "[warning]: Unsupported encryption mode encountered in RECOVERY_STRUCT index=" << i << "." << endl;
            continue;
        }

        //derive secondary key
        unique_ptr<Botan::HashFunction> sha(Botan::HashFunction::create("SHA-256"));
        uint32_t cur_size = 0;
        while(cur_size < SHA_INPUT_SIZE){
            //add salt
            sha->update(cur_rec_struct + 0x8ec, min((uint32_t)8, SHA_INPUT_SIZE - cur_size));
            cur_size += 8;
            if(cur_size >= SHA_INPUT_SIZE)
                break;
            //add password
            sha->update((uint8_t *)password, min(password_len, SHA_INPUT_SIZE - cur_size));
            cur_size += password_len;
        }
        Botan::secure_vector<uint8_t> secondary_key = sha->final();

        //try decrypting all the KEY_AND_HASH structures
        for(uint32_t kah = 0; kah < sizeof(key_struct_offsets) / sizeof(key_struct_offsets[0]); kah++) {
            uint32_t kah_offset = key_struct_offsets[kah];
            Botan::secure_vector<uint8_t> master_key_and_hash(cur_rec_struct + kah_offset, cur_rec_struct + kah_offset + 0x60);
            if (decrypt_key_and_hash(master_key_and_hash, secondary_key, cur_encryption_type)) {
                //fill out arguments
                enc_keys.resize(0x40);
                memcpy(enc_keys.data(), master_key_and_hash.data(), 0x40);
                encryption_type = cur_encryption_type;
                encrypted_boot_sector.resize(SECTOR_SIZE);
                memcpy(encrypted_boot_sector.data(), cur_rec_struct + 0x628, SECTOR_SIZE);
                matching_structs++;
                last_matching_struct = i;
                break;
            }
        }
    }

    //wipe the password from memory
#ifdef __STDC_LIB_EXT1__
    set_constraint_handler_s(ignore_handler_s); //none of the specified constraints can happen here
    memset_s(password, password_len, 0, password_len);
#else
    memset(password, 0, password_len);
#endif
    //to prevent -O2 compiler optimizations
    uint32_t password_or = 0;
    for(uint32_t i = 0; i < password_len; i++){
        password_or |= password[i];
    }
    if(password_or != 0)
        cerr << "[warning]: The provided password was not wiped from memory." << endl;

    
    rscf.close();
    if(matching_structs == 0) {
        cerr << "[error]: The provided password is not used in the provided rescue file." << endl;
        return false;
    }
    if(matching_structs != 1)
        cerr << "[warning]: Multiple (" << matching_structs << ") active RECOVERY_STRUCTs are protected with the provided password. Decryption will be performed using RECOVERY_STRUCT index "
             << last_matching_struct << ". If you'd like to use another RECOVER_STRUCT for decryption, please use the -i command line argument." << endl;
    return true;
}