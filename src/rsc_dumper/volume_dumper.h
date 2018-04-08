#pragma once

#include <cstdint>

//contains value of the command line argument -v
extern bool verbose_mode;

//prints info about a single RECOVERY_STRUCT
void dump_volume(const uint8_t* rec_struct);
