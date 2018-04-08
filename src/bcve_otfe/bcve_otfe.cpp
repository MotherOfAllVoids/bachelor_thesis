#include <vector>
#include <iostream>
#include <fstream>
#include <cstdlib>
#include <unistd.h>

#include <botan/block_cipher.h>
#include <botan/cipher_mode.h>
#include <botan/hex.h>

#include "BUSE-master/buse.h"
#include "bcve_rsc_parser.h"



using namespace std;

//preprocesses the sector number for XTS to pass to botan
class tweak_preprocessor{
    union tweak {
        uint64_t tw_i[BLOCK_CIPHERS_BLOCK_SIZE/8];
        uint8_t tw_b[BLOCK_CIPHERS_BLOCK_SIZE];
    } tw;
public:
    tweak_preprocessor(){
        memset(tw.tw_b, 0, BLOCK_CIPHERS_BLOCK_SIZE);
    }

    //for volumes bigger than 2^73 bytes, a more robust solution is needed
    void set_sector_num(uint64_t sector_num){
        //make sure it's in little endian
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        sector_num = __builtin_bswap64 (sector_num);
#endif
        tw.tw_i[0] = sector_num;
    }

    void increment_sector_num(){
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        tw.tw_i[0] = __builtin_bswap64 (tw.tw_i[0]);
#endif
        tw.tw_i[0]++;
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        tw.tw_i[0] = __builtin_bswap64 (tw.tw_i[0]);
#endif
    }

    const uint8_t* get_tweak(){
        return tw.tw_b;
    }
};

//pointer to this struct is passed to all buse_operation callbacks
struct op_ctx{
    std::unique_ptr<Botan::Cipher_Mode> encryptor; //for XTS encryption on write operations
    std::unique_ptr<Botan::Cipher_Mode> decryptor; //for XTS decryption on read operations
    fstream encrypted_device; //stream to the file that holds the encrypted volume
    uint64_t offset_into_encrypted_device; //offset, where the encrypted volume starts within a disk
    tweak_preprocessor tweak; //converts the tweak to a format Botan expects
    uint8_t boot_sector_enc[SECTOR_SIZE]; //encrypted first sector of the volume (as read from the rescue file)

    op_ctx(Botan::secure_vector<uint8_t> enc_keys, std::vector<uint8_t> encrypted_boot_sector, 
           string encryption_type, uint64_t offset)
       : encryptor(Botan::get_cipher_mode(encryption_type + "/XTS", Botan::ENCRYPTION))
       , decryptor(Botan::get_cipher_mode(encryption_type + "/XTS", Botan::DECRYPTION))
       , offset_into_encrypted_device(offset)
    {
        memcpy(boot_sector_enc, encrypted_boot_sector.data(), SECTOR_SIZE);
        encryptor->set_key(enc_keys);
        decryptor->set_key(enc_keys);
    }
};

static void usage()
{
    cerr << "Usage: bcve_otfe [<options>] <encrypted_disk> <virtual_device> <rescue_file>" << endl << endl;
    cerr << "Options:" << endl;
    cerr << "-i\tIndex of the RECOVERY_STRUCT to use. Use this option if there are multiple RECOVERY_STRUCTs protected with the same password." << endl;
    cerr << "-o\tOffset in bytes of the start of the encrypted volume within encrypted_disk. Default value is zero." << endl;
    cerr << "-s\tSize of the encrypted volume. Defaults to the whole encrypted_disk." << endl;
}

static int bcve_read(void *buf, uint32_t len, uint64_t offset, void *userdata)
{
    if(len == 0)
        return 0;
    if(len % SECTOR_SIZE || offset % SECTOR_SIZE) {
        //I don't think this should happen, since nbd operates on blocks of 1024 bytes
        cerr << "[warning]: An unaligned read detected. Please note that all read offsets and lengths must be a multiple of "
             << SECTOR_SIZE << "." << endl;
        return 1;
    }
    struct op_ctx* ctx = (struct op_ctx*) userdata;
    ctx->encrypted_device.seekg(offset + ctx->offset_into_encrypted_device);
    ctx->encrypted_device.read((char *)buf, len);

    //load the boot sector that we got from the rescue file
    if(offset == 0 && len >= SECTOR_SIZE)
        memcpy(buf, ctx->boot_sector_enc, SECTOR_SIZE);

    ctx->tweak.set_sector_num(offset / SECTOR_SIZE);
    for(uint32_t pos = 0; pos < len; pos += SECTOR_SIZE){
        ctx->decryptor->start(ctx->tweak.get_tweak(), BLOCK_CIPHERS_BLOCK_SIZE);
        Botan::secure_vector<uint8_t> pt((uint8_t *)buf + pos, (uint8_t *)buf + pos + SECTOR_SIZE);
        ctx->decryptor->finish(pt);
        memcpy((uint8_t *)buf + pos, pt.data(), SECTOR_SIZE);
        ctx->tweak.increment_sector_num();
    }
    return 0;
}

static int bcve_write(const void *buf, uint32_t len, uint64_t offset, void *userdata)
{
    if(len == 0)
        return 0;
    if(len % SECTOR_SIZE || offset % SECTOR_SIZE) {
        cerr << "[warning]: An unaligned write detected. This write is not going to be written through to the encrypted image. Please note that all write offsets and lengths must be a multiple of "
             << SECTOR_SIZE << "." << endl;
        return 1;
    }
    if(offset == 0) {
        //I could potentially write the first sector directly to the rescue file, but that would create inconsistencies between what is in the rescue file and what BCVE thinks is in the first sector
        cerr << "[warning]: Write to the first sector detected. This write is not going to be written through to the encrypted image." << endl;
        return 1;
    }
    struct op_ctx* ctx = (struct op_ctx*) userdata;

    ctx->tweak.set_sector_num(offset / SECTOR_SIZE);
    for(uint32_t pos = 0; pos < len; pos += SECTOR_SIZE){
        ctx->encryptor->start(ctx->tweak.get_tweak(), BLOCK_CIPHERS_BLOCK_SIZE);
        Botan::secure_vector<uint8_t> pt((uint8_t *)buf + pos, (uint8_t *)buf + pos + SECTOR_SIZE);
        ctx->encryptor->finish(pt);
        memcpy((uint8_t *)buf + pos, pt.data(), SECTOR_SIZE);
        ctx->tweak.increment_sector_num();
    }

    ctx->encrypted_device.seekg(offset + ctx->offset_into_encrypted_device);
    ctx->encrypted_device.write((const char *)buf, len);
    return 0;
}

static int bcve_flush(void *userdata)
{
    struct op_ctx* ctx = (struct op_ctx*) userdata;
    ctx->encrypted_device.flush();
    return 0;
}

static struct buse_operations bop = {
    bcve_read,
    bcve_write,
    NULL,
    bcve_flush,
    NULL,  //don't need trim
    0
};

static void parse_cl_param_value(const char * string_val, char opt, uint64_t& out){
    errno = 0;
    char * tmp;
    out = strtoull(string_val, &tmp, 0);
    if(errno != 0 || tmp == string_val){
        cerr << "[error]: Invalid value for -" << opt << " -> " << string_val << endl;
        usage();
        exit(1);
    }
}

int main(int argc, char *argv[])
{
    uint64_t offset = 0, vol_size = 0, recstruct_index = UINT64_MAX;
    int  c;
    //parse CL
    while ((c = getopt (argc, argv, "o:s:i:")) != -1){
        switch (c)
        {
            case 'o':
                parse_cl_param_value(optarg, 'o', offset);
                break;
            case 's':
                parse_cl_param_value(optarg, 's', vol_size);
                break;
            case 'i':
                parse_cl_param_value(optarg, 'i', recstruct_index);
                break;
            case '?':
                if (optopt == 'o' || optopt == 's' || optopt == 'i')
                    cerr << "[error]: Option -" << optopt << " requires an argument." << endl;
                else
                    cerr << "[error]: Unknown option `- "<< optopt << "'." << endl;
                usage();
                return 1;
            default:
                abort ();
        }
    }

    
    if (argc - optind != 3) {
        usage();
        return 1;
    }

    Botan::secure_vector<uint8_t> enc_keys;
    std::vector<uint8_t> encrypted_boot_sector;
    uint8_t encryption_type;

    if(!parse_rescue_file(argv[optind + 2], recstruct_index, enc_keys, encrypted_boot_sector, encryption_type)){
        cerr << "[error]: Could not extract all needed information from the rescue file!" << endl;
        return 1;
    }


    //create encryption context
    struct op_ctx to_pass(enc_keys, encrypted_boot_sector, cipher_enum[encryption_type - 8], offset);

    //open it at the end, so I can tell the size of the underlying device
    to_pass.encrypted_device.open(argv[optind], ios::binary | ios::ate | ios::in | ios::out);
    if(to_pass.encrypted_device.fail()){
        cerr << "[error]: Could not open " << argv[optind] << endl;
        return 1;
    }

    unsigned long size = to_pass.encrypted_device.tellg();
    
    if(offset >= size || offset + vol_size >= size){
        cerr << "[error]: Invalid choice of -o and -s parameters. They overflow the size of the underlying encrypted file." << endl;
        to_pass.encrypted_device.close();
        usage();
        return 1;
    }
    
    //if the user does not specify vol_size, use the entire volume starting from offset
    if(vol_size == 0)
        bop.size = size - offset; 
    else
        bop.size = vol_size;

    //actually create the block device
    int to_return = buse_main(argv[optind + 1], &bop, (void *)(&to_pass));
    to_pass.encrypted_device.close();
    return to_return;
}
