#pragma once

#include <botan/block_cipher.h>
#include <botan/cipher_mode.h>
#include <botan/hash.h>
#include <botan/hex.h>
#include <vector>
#include <string>

#define SECTOR_SIZE 512 //the sector size that BCVE operates on (BCVE divides 4K sectors into eight 512B sectors for XTS too)
#define BLOCK_CIPHERS_BLOCK_SIZE 16 //all currently supported ciphers operate on 128-bit blocks

extern std::string cipher_enum[];

//opens the file name rsc_file_name and attempts to fill out three out parameters
//if recstruct_index is not set to UINT64_MAX, only the RECOVERY_STRUCT with the specified index is going to be parsed
bool parse_rescue_file(const char* rsc_file_name, uint64_t recstruct_index, Botan::secure_vector<uint8_t>& enc_keys, std::vector<uint8_t>& encrypted_boot_sector, uint8_t& encryption_type);
