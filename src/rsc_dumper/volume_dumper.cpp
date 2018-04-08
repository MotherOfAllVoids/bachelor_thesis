#define __STDC_WANT_LIB_EXT1__ 1
#include "volume_dumper.h"
#include "sha2_hasher.h"
#include "decryptor.h"
#include <list>
#include <iostream>
#include <string>
#include <iomanip>
#include <sstream>
#include <unistd.h>
#include <algorithm>

#define SHA256_OUTPUT_SIZE 32
#define BLOCK_CIPHERS_BLOCK_SIZE 16
#define SECTOR_SIZE 512
using namespace std;

uint8_t RECOVERY_STRUCT_MAGIC[16]     = {0x74, 0x0e, 0x0d, 0x8d, 0xe7, 0x5b, 0x13, 0x57, 0xf8, 0x72, 0x16, 0x71, 0xaf, 0x53, 0x7d, 0x5d};
uint8_t KEY_STRUCT_MAGIC[16]          = {0xdd, 0xa2, 0x6a, 0x7e, 0x3a, 0x59, 0xff, 0x45, 0x3e, 0x35, 0x0a, 0x44, 0xbc, 0xb4, 0xcd, 0xd5};
uint8_t ADDITIONAL_PASSWORD_MAGIC[16] = {0x72, 0xea, 0xce, 0xa8, 0xfa, 0x64, 0x84, 0xbb, 0x8d, 0x66, 0x12, 0xae, 0xbf, 0x3c, 0x6f, 0x47};

const string volume_types[] = {"", "Simple", "Spanned", "Striped", "Mirrored", "RAID-5"};

//check if BCVE would even accept this password
static bool check_pwd(const char * pwd) {
	uint32_t pwd_len = strlen(pwd);
	if(pwd_len < 8 || pwd_len > 190)
		return false;
	for(uint32_t i = 0; i < pwd_len; i++){
		if ((unsigned char)pwd[i] > 0x7E) //any char that is not 7-bit ASCII and DEL is forbidden
			return false;
	}
	return true;
}

//prints anything that can be printed with cout
template <typename T>
static void print_stuff(const string desc, const T value, bool only_verbose) {
	if (only_verbose && !verbose_mode) 
		return;  //verbose value in nonverbose mode
	if (only_verbose)
		cout << "//";
	else
		cout << "--";
	//print bools as "true" or "false"
	cout << desc << ": " << std::boolalpha << value << endl;
}

static bool check_if_whole_buffer_is_zero(const uint8_t * buf, uint32_t len){
	for(uint32_t i = 0; i < len; i++){
		if(buf[i])
			return false;
	}
	return true;
}

//prints a hexadecimal string representing a buffer
static void print_bytes(string desc, const uint8_t* buf, int len, bool only_verbose) {
	if(check_if_whole_buffer_is_zero(buf, len)){
		print_stuff(desc, "[empty buffer]", only_verbose);
		return;
	}
	ostringstream  ss;
	for (int i = 0; i < len; i++)
		ss << hex << setfill('0') << setw(2) << (int)buf[i];
	print_stuff(desc, ss.str(), only_verbose);
}

static void print_timestamp(const uint8_t* packed_tmpstmp) {
	//QWORD - 3bytes for the year, 1 byte for month, day, hour, minute and second
	ostringstream  ss;
	ss << (int)packed_tmpstmp[3] << ". " << (int)packed_tmpstmp[4] << ". " << (*(uint32_t *)(packed_tmpstmp + 4) >> 8);
	ss << setfill('0') << setw(2) << "  " << (int)packed_tmpstmp[2] << ":" << setfill('0') << setw(2) << (int)packed_tmpstmp[1] 
		<< ":" << setfill('0') << setw(2) << (int)packed_tmpstmp[0];
	print_stuff("Rescue file last modification [UTC]", ss.str(), false);
}

//warning: reads eight bytes instead of six!!
static uint64_t get_six_byte_integer(const uint8_t * p){
	return *(uint64_t *)p & 0xFFFFFFFFFFFF; 
}

static void print_transform_iv_way(uint8_t b){
	string mode = "Unknown";
	switch(b & 0x0F){
		case 0:
			mode = "CBC";
			break;
		case 4:
			mode = "LRW";
			break;
		case 8:
			mode = "XTS";
			break;
	}
	print_stuff("Mode of operation", mode, true);
	print_stuff("Uses LBAs for tweaks", !(b & 0x10), false);
}

static void dump_disk_extent(const uint8_t* disk_extent){
	if(memcmp(disk_extent, KEY_STRUCT_MAGIC, 0x10))
		print_bytes("!!INVALID KEY_STRUCT MAGIC", disk_extent, 0x10, false);

	print_stuff("--LBA of the first sector", get_six_byte_integer(disk_extent + 0x10), false);
	print_stuff("--LBA of the last sector", get_six_byte_integer(disk_extent + 0x16), false);
	print_stuff("--Extent size in sectors", get_six_byte_integer(disk_extent + 0x1C), false);

	//if this volume is partitioned with MBR, the last 12 bytes of disk id are cleared
	if(check_if_whole_buffer_is_zero(disk_extent + 0x26, 0xC))
		print_bytes("--MBR signature", disk_extent + 0x22, 0x4, false);
	else
		print_bytes("--Disk GUID", disk_extent + 0x22, 0x10, false);
		

	print_stuff("--Windows disk number", (uint32_t)disk_extent[0x32], false);
	print_stuff("--BIOS disk number", (uint32_t)disk_extent[0x35], false);

	//if replaced sector LBA is set to -1, there is no replaced sector on this disk extent
	if(get_six_byte_integer(disk_extent + 0x38) != 0xFFFFFFFFFFFF)
		print_stuff("--LBA of the replaced sector", get_six_byte_integer(disk_extent + 0x38), false);
}

//assumes that block_cipher_type is set to a supported block cipher
static bool dump_key_and_hash(const Botan::secure_vector<uint8_t>& secondary_key,const uint8_t* key_and_hash_encrypted, const uint8_t *first_sector_encrypted, uint8_t block_cipher_type){
	if( *(uint32_t *)key_and_hash_encrypted == 0x99FFAAEE && check_if_whole_buffer_is_zero(key_and_hash_encrypted + 4, 0x3C)){
		cout << "!!Two factor authentication is enabled!" << endl;
		return false;
	}

	//decrypt in CBC mode
	Botan::secure_vector<uint8_t> key_and_hash(0x60);
	memcpy(key_and_hash.data(), key_and_hash_encrypted, 0x60);
	decrypt_key_and_hash(key_and_hash, secondary_key, block_cipher_type);

	//check hash
	Botan::secure_vector<uint8_t>  key_and_hash_checksum = hash_buffer(key_and_hash.data(), 0x40, true);
	if(memcmp(key_and_hash_checksum.data(), key_and_hash.data() + 0x40, SHA256_OUTPUT_SIZE))
		return false;

	print_bytes("XTS primary key", key_and_hash.data(), 0x20, false);
	print_bytes("XTS tweak key", key_and_hash.data() + 0x20, 0x20, false);

	//decrypt first sector
	unique_ptr<Botan::Cipher_Mode> decryptor(Botan::get_cipher_mode(block_cipher_enum[block_cipher_type] + "/XTS", Botan::DECRYPTION));
	decryptor->set_key(Botan::secure_vector<uint8_t>(key_and_hash.begin(), key_and_hash.begin() + 0x40));

	uint8_t empty_tweak[BLOCK_CIPHERS_BLOCK_SIZE] = {0}; //first sector has the tweak set to 0
	decryptor->start(empty_tweak, BLOCK_CIPHERS_BLOCK_SIZE);
    
    Botan::secure_vector<uint8_t> first_sector_decrypted(first_sector_encrypted, first_sector_encrypted + SECTOR_SIZE);
    decryptor->finish(first_sector_decrypted);

    print_bytes("Decrypted first sector", first_sector_decrypted.data(), SECTOR_SIZE, false);
    return true;
}

void dump_volume(const uint8_t* rsc_block) {
	if(memcmp(rsc_block, RECOVERY_STRUCT_MAGIC, 0x10))
		print_bytes("!!INVALID RECOVERY_STRUCT MAGIC", rsc_block, 0x10, false);

	uint32_t number_of_disk_extents = *(uint32_t *)(rsc_block + 0x410);
	print_stuff("Number of disk extents", number_of_disk_extents, false);

	if(rsc_block[0x44] <= 5)
		print_stuff("Volume type", volume_types[rsc_block[0x44]], false);

	for(uint32_t i = 0; i < 8 && i < number_of_disk_extents; i++){
		cout << "--Disk extent #" << i << ":" <<  endl;
		dump_disk_extent(rsc_block + 0x10 + 0x40 * i);
	}

	print_stuff("Permanently decrypted", rsc_block[0x414] != 0, false); 

	print_bytes("MBR signature on an EFI disk", rsc_block + 0x438, 0x40, true);
	print_bytes("Location of UEFI dummy files", rsc_block + 0x478, 0xC, true);
	print_stuff("Remote administrator owns a recovery password", (bool)(*(uint32_t*)(rsc_block + 624) & 0x2), true);
	print_transform_iv_way(rsc_block[0x8E8]);

	const uint8_t* salt = rsc_block + 0x8EC;
	uint8_t block_cipher_type = rsc_block[0x8E9];
	print_stuff("Block cipher", block_cipher_enum[block_cipher_type], false);
	print_stuff("System volume flag", rsc_block[0x8EA] == 1 , false);
	print_stuff("Boot volume flag", rsc_block[0x8EB] == 1, false);
	print_bytes("Password salt", salt, 8, true);
	print_bytes("Original boot sector", rsc_block + 0x8F4, 0x200, false);
	print_bytes("key_and_hash_pubkey_master", rsc_block + 0x210, 0x200 , true);
	print_timestamp(rsc_block + 0x61C);

	//check which additional passwords are present
	list<uint32_t> additional_password_slots;
	if(!memcmp(rsc_block + 0xAF4, KEY_STRUCT_MAGIC, 0x10) && !memcmp(rsc_block + 0xB04, ADDITIONAL_PASSWORD_MAGIC, 0x10))
		for(uint32_t i = 0; i < 4; i++)
			if(*(uint32_t *)(rsc_block + 0xB74 + 0x64 * i) == 2)
				additional_password_slots.push_back(i);

	print_stuff("Number of additional passwords", additional_password_slots.size(), false);

	char* user_pwd = getpass("Enter a password for this recovery struct: ");
	//validate the password
	if (check_pwd(user_pwd)) {
		Botan::secure_vector<uint8_t> secondary_key = hash_pwd(user_pwd, salt);
		print_bytes("Secondary key", secondary_key.data(), SHA256_OUTPUT_SIZE, true);
		
		if(block_cipher_type >= 8 && block_cipher_type <= 10) {
			//try master password key and hash
			bool decrypted = dump_key_and_hash(secondary_key, rsc_block + 0x828, rsc_block + 0x628, block_cipher_type);

			//try remote admin key and hash
			if(!decrypted)
				decrypted = dump_key_and_hash(secondary_key, rsc_block + 0x888, rsc_block + 0x628, block_cipher_type);

			//additional key and hash structures
			for (auto i = additional_password_slots.begin(); i != additional_password_slots.end(); i++)
				if(!decrypted)
			    	decrypted = dump_key_and_hash(secondary_key, rsc_block + 0xB14 + (*i) * 0x64, rsc_block + 0x628, block_cipher_type);
	
			if (decrypted)
				cout << "You entered a correct password!" << endl;
			else
				cout << "You entered an INcorrect password!" << endl;
			
		}else{
			cout << "!!This RECOVERY_STRUCT is encrypted with an unsupported block cipher." << endl;
		}
	}else{
		cout << "!!The password you entered is not a valid password and BCVE would not accept it!!" << endl;
	}

    //wipe the password from memory
    uint32_t password_len = strlen(user_pwd);
#ifdef __STDC_LIB_EXT1__
    set_constraint_handler_s(ignore_handler_s); //none of the specified constraints can happen here
    memset_s(user_pwd, password_len, 0, password_len);
#else
    memset(user_pwd, 0, password_len);
#endif
    //to prevent -O2 compiler optimizations
    uint32_t password_or = 0;
    for(uint32_t i = 0; i < password_len; i++){
        password_or |= user_pwd[i];
    }
    if(password_or != 0)
        cerr << "[warning]: The provided password was not wiped from memory." << endl;
}
