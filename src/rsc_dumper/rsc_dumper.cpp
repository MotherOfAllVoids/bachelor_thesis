#include <iostream>
#include <fstream>
#include <cstdint>
#include <cstring>
#include "volume_dumper.h"

#define RECOVERY_STRUCT_SIZE 0xCF4
using namespace std;

bool verbose_mode;

static void usage()
{
    cerr << "Usage: rsc_dumper [-v] <rescue_file>" << endl;
}

int main(int argc, char *argv[])
{
	uint8_t recovery_struct[RECOVERY_STRUCT_SIZE];

	if (argc != 2 && !(argc == 3 && !strncmp(argv[1], "-v", 2))){
		usage();
		return 1;
	}
	
	verbose_mode = argc != 2;

	//if verbose_mode is set, rsc file name is the second argument...
	ifstream rscf(argv[1 + verbose_mode], ios::in | ios::binary | ios::ate);
	if (!rscf.is_open()) {
		cerr << "Can't open " << argv[1 + verbose_mode] << endl;
		usage();
		return 1;
	}

	uint64_t rscf_size = rscf.tellg();
	if (rscf_size % RECOVERY_STRUCT_SIZE) {
		cerr << "Corrupt rsc file" << endl;
		usage();
		return 1;
	}

	rscf.seekg(0, ios::beg);

	//read RECOVERY_STRUCTS one by one
	int volume_num = 0;
	while (1) {
		rscf.read((char *)recovery_struct, RECOVERY_STRUCT_SIZE);
		if (!rscf)
			break;
		if (volume_num != 0)
			cout << "================================================" << endl;
		cout << "Recovery struct #" << volume_num << ": " << endl;
		dump_volume(recovery_struct);
		volume_num++;
	}


	rscf.close();
    return 0;
}

