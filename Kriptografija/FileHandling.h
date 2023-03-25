#pragma once

#include <cstdlib>
#include <ctime>
#include <vector>
#include <cctype>


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


// Encrypts and stores the key in a file
void writeKey(std::vector<BYTE>, string, string);


// Writes iv to a file
void writeIv(std::vector<BYTE>, string, string);