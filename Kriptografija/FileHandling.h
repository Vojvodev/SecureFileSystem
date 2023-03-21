#pragma once

#include <cstdlib>
#include <ctime>
#include <vector>



#include <openssl/rand.h>


typedef unsigned char BYTE;



// Takes your file and dissects it into smaller pieces and stores it somewhere, param. user name
int upload(string);

// Reads a file and returns a vector of BYTEs, param. filePath
std::vector<BYTE> readFile(const char*);

// Returns encrypted vector of BYTEs, param. vector to be encrypted, key, iv
std::vector<BYTE> encrypt(std::vector<BYTE>, std::vector<BYTE>, std::vector<BYTE>);

// Writes out all the files for one user, param. that user
void listFiles(string);



int download();
