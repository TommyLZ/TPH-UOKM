#include "KeyGen.h"
#include "PublicParam.h"

#include <pbc/pbc.h>
#include <cstring>
#include <fstream>
#include <iostream>

extern pairing_t pairing;
extern element_t P;

extern int n;
extern int t;

using namespace std;

void save_keys_to_file(element_t *keys, const char *filename)
{
    std::ofstream outfile(filename, std::ios::binary);

    for (int i = 1; i <= n; i++)
    {
        size_t key_size = element_length_in_bytes(keys[i]);
        unsigned char key_bytes[key_size];
        element_to_bytes(key_bytes, keys[i]);
        outfile.write((char *)key_bytes, key_size);
    }

    outfile.close();
}

void KeyGen(char *pw)
{
	cout << "***********************************KeyGen Phase*************************************" << endl;
    
    // Select a random
    element_t s_eta;
    element_init_Zr(s_eta, pairing);
    element_random(s_eta);

    // User-specific random key
    element_t user_public_key;
    element_init_G1(user_public_key, pairing);
    element_pow_zn(user_public_key, P, s_eta);
    save_key_to_file(user_public_key, "../Store/user_public_key.bin");

    // Compute shares of s_eta
    element_t shares[n + 1]; // Record the shares
    element_t coeff[t];      // Coefficient
    // element_printf("The secret shared is %B \n", s_eta);
    secretShare(s_eta, shares, coeff);
    // for (int i = 1; i <= t; i++)
    // {
    //     element_printf("the %dth share is %B\n", i, shares[i]);
    // }
    save_keys_to_file(shares, "../Store/shared_secret_key.bin");

    element_t shared_public_key[n + 1];
    for (int i = 1; i <= n; i++)
    {
        element_init_G1(shared_public_key[i], pairing);
        element_pow_zn(shared_public_key[i], P, shares[i]);
    }
    save_keys_to_file(shared_public_key, "../Store/shared_public_key.bin");

    element_t h_2;
    element_init_G1(h_2, pairing);
    element_from_hash(h_2, pw, strlen(pw));
    // element_printf("h_2=%B\n", h_2);

    element_t s_eta_mul_h2;
    element_init_G1(s_eta_mul_h2, pairing);
    element_pow_zn(s_eta_mul_h2, h_2, s_eta);
    // element_printf("sigma=%B\n", s_eta_mul_h2);

    // Transform element_t to char*
    char s_eta_mul_h2_str[1024];
    element_snprint(s_eta_mul_h2_str, sizeof(s_eta_mul_h2_str), s_eta_mul_h2);
    char *input = new char[strlen(pw) + strlen(s_eta_mul_h2_str) + 1];
    strcpy(input, pw);
    strcat(input, s_eta_mul_h2_str);

    // Computes the password-derived key
    element_t SK;
    element_init_Zr(SK, pairing);
    element_from_hash(SK, input, strlen(input));
    // element_printf("SK=%B\n", SK);

    // Computes the public key
    element_t PK;
    element_init_G1(PK, pairing);
    element_pow_zn(PK, P, SK);
    // element_printf("P=%B\n", P);
    // element_printf("PK=%B\n", PK);

    // Store
    save_key_to_file(PK, "../Store/PK.bin");

    cout << "Key generation finished!" << endl;
}