#pragma once

#include <cryptopp/integer.h>
#include <pbc/pbc.h>

using namespace std;
using namespace CryptoPP;

void paramSetup();

void save_key_to_file(element_t key, const char *filename);

void load_keys_from_file(element_t *keys, const char *filename);
void load_keyi_from_file(element_t& key, const char *filename);

void secretRecover(element_t& recover_secret, element_t share[]);
void genLagrange(element_t lagrange[]);
void secretShare(element_t &secret, element_t shares[], element_t coeff[]);

void saveDataToBinFile(element_t R, element_t tau, const string &cipher, const char *fileName);
bool loadDataFromBinFile(element_t &R, element_t &tau, string &cipher, const char *fileName);

// AES_CBC encryption operation
void aes_CBC_Enc(const string &plain, const CryptoPP::byte *key, const CryptoPP::byte *iv, string &cipher);

// AES_CBC decryption operation
void aes_CBC_Dec(const string &cipher, const CryptoPP::byte *key, const CryptoPP::byte *iv, string &plain);