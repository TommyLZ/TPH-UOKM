#include "Encryption.h"
#include "PublicParam.h"

#include <iostream>
#include <fstream>
#include <cryptopp/files.h>
#include <cryptopp/hex.h>
#include <cryptopp/osrng.h>

using namespace std;

extern pairing_t pairing;
extern element_t P;

void load_key_from_file(element_t& key, const char *filename)
{
    std::ifstream infile(filename, std::ios::binary);
    infile.seekg(0, infile.end);
    size_t key_size = infile.tellg();
    infile.seekg(0, infile.beg);
    unsigned char key_bytes[key_size];
    infile.read((char *)key_bytes, key_size);
    element_from_bytes(key, key_bytes);
    infile.close();
}

void Encryption(char* pw) 
{
	cout << "***********************************Encryption Phase*********************************" << endl;

    // Select a random
    element_t r;
    element_init_Zr(r, pairing);
    element_random(r);

    // Computes a wrap
    element_t R;
    element_init_G1(R, pairing);
    element_pow_zn(R, P, r);
    
    // load the PK
    element_t PK;
    element_init_G1(PK, pairing);
    load_key_from_file(PK, "../Store/PK.bin");
    // element_printf("PK=%B\n", PK);

    // Caculate a symmetric key
    element_t h_input;
    element_init_G1(h_input, pairing);
    element_pow_zn(h_input, PK, r);
    // element_printf("The input is %B\n", h_input);
    
    // Transform element_t to char*
    char h_input_str[1024];
    element_snprint(h_input_str, sizeof(h_input), h_input);
    // cout << "h_input_str" << h_input_str << endl;

    element_t ek;
    element_init_Zr(ek, pairing);
    element_from_hash(ek, h_input_str, strlen(h_input_str));
    // element_printf("The ek is %B\n", ek);
    
    char ek_str[1024];
    element_snprint(ek_str, 33, ek);
    // cout << "ek_str: " << ek_str << endl;
   
    // Generate the symmetric key and encrypt
    CryptoPP::byte ek_aes[16];
    CryptoPP::StringSource(ek_str, true, new CryptoPP::HexDecoder(new CryptoPP::ArraySink(ek_aes, 16)));

    AutoSeededRandomPool dsk_prng;
    CryptoPP::byte iv[16];
    dsk_prng.GenerateBlock(iv, 16);
    
    CryptoPP::FileSink fileSink("../Store/iv.bin", true);  // true 表示追加到文件末尾
    fileSink.Put(iv, sizeof(iv));

    string plain = "Hello! Nice to meet you!";
    string cipher;
    aes_CBC_Enc(plain, ek_aes, iv, cipher);

    string ekStr;
    CryptoPP::ArraySource(ek_aes, 16, true, new CryptoPP::HexEncoder(new CryptoPP::StringSink(ekStr)));
    const char* ekCharPtr = ekStr.c_str();
    const char* plainCharPtr = plain.c_str();

    char* tag_input = new char [strlen(ekCharPtr) + strlen(plainCharPtr) + 1];
    strcpy(tag_input, ekCharPtr);
    strcat(tag_input, plainCharPtr);

    // Compute the tag
    element_t tau;
    element_init_Zr(tau, pairing);
    element_from_hash(tau, tag_input, strlen(tag_input));

    // Store
    saveDataToBinFile(R, tau, cipher, "../Store/CS_store.bin");

    cout << "Data encryption finished!" << endl;
}