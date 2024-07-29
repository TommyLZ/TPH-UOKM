#include "Decryption.h"
#include "PublicParam.h"

#include <pbc/pbc.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>
#include <cryptopp/osrng.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>

using namespace std;

extern pairing_t pairing;
extern element_t P;

extern int n;
extern int t;


void Decryption(char *pw)
{
	cout << "***********************************Decryption Phase*********************************" << endl;
    
    element_t R;
    element_init_G1(R, pairing);

    element_t tau;
    element_init_Zr(tau, pairing);

    string cipher;

    if (loadDataFromBinFile(R, tau, cipher, "../Store/CS_store.bin"))
    {
        cerr << "Succeed to read data from CS_store.bin" << endl;
    }
    else
    {
        cerr << "Failed to read data from CS_store.bin" << endl;
    }

    /**************************************************************************************************/

    element_t beta;
    element_init_Zr(beta, pairing);
    element_random(beta);

    element_t beta_inverse;
    element_init_Zr(beta_inverse, pairing);
    element_invert(beta_inverse, beta);

    element_t h_2;
    element_init_G1(h_2, pairing);
    element_from_hash(h_2, pw, strlen(pw));
    // element_printf("h_2=%B\n", h_2);

    element_t blind_pw;
    element_init_G1(blind_pw, pairing);
    element_pow_zn(blind_pw, h_2, beta);
    // element_printf("The blinded password is %B\n", blind_pw);

    element_t shares[t + 1];
    for (int i = 1; i <= t; i++)
    {
        element_init_Zr(shares[i], pairing);
    }
    load_keys_from_file(shares, "../Store/shared_secret_key.bin");
    // for (int i = 1; i <= t; i++)
    // {
    //     element_printf("the %dth share is %B\n", i, shares[i]);
    // }

    element_t sigma_eta[t + 1];
    for (int i = 1; i <= t; i++)
    {
        element_init_G1(sigma_eta[i], pairing);
        element_pow_zn(sigma_eta[i], blind_pw, shares[i]);
        // element_printf("the %dth share is %B\n", i, shares[i]);
        // element_printf("The blinded password is %B\n", blind_pw);
        // element_printf("The sigma_eta[i] is %B\n", sigma_eta[i]);
    }

    // element_t h_2_inverse;
    // element_init_G1(h_2_inverse, pairing);
    // element_invert(h_2_inverse, h_2);

    // element_t newshares[t + 1];
    // for (int i = 1; i <= t; i++)
    // {
    //     element_init_Zr(newshares[i], pairing);
    //     element_mul(newshares[i], sigma_eta[i], h_2_inverse);
    //     element_mul(newshares[i], newshares[i], beta_inverse);
    // }

    // element_t s_eta;
    // element_init_Zr(s_eta, pairing);
    
    // secretRecover(s_eta, newshares);
    // element_printf("The recovered secret is %B\n", s_eta);

    element_t shared_public_key[t + 1];
    for (int i = 1; i <= t; i++)
    {
        element_init_G1(shared_public_key[i], pairing);
    }
    load_keys_from_file(shared_public_key, "../Store/shared_public_key.bin");

    for (int i = 1; i <= t; i++)
    {
        element_t tmp1, tmp2;
        element_init_GT(tmp1, pairing);
        element_init_GT(tmp2, pairing);

        pairing_apply(tmp1, sigma_eta[i], P, pairing);
        pairing_apply(tmp2, blind_pw, shared_public_key[i], pairing);

        if (element_cmp(tmp1, tmp2))
        {
            cout << "Signature from each key server " << i << " fails!" << endl;
        }
    }

    element_t sum;
    element_init_G1(sum, pairing);
    secretRecover(sum, sigma_eta);

    element_t sigma;
    element_init_G1(sigma, pairing);
    element_pow_zn(sigma, sum, beta_inverse);

    element_t user_public_key;
    element_init_G1(user_public_key, pairing);
    load_keyi_from_file(user_public_key, "../Store/user_public_key.bin");

    element_t tmp1, tmp2;
    element_init_GT(tmp1, pairing);
    element_init_GT(tmp2, pairing);

    pairing_apply(tmp1, sigma, P, pairing);
    pairing_apply(tmp2, h_2, user_public_key, pairing);

    if (!element_cmp(tmp1, tmp2))
    {
        cout << "Combined signature verifies!" << endl;
    }    

    // Transform element_t to char*
    char sigma_str[1024];
    element_snprint(sigma_str, sizeof(sigma), sigma);
    char *input = new char[strlen(pw) + strlen(sigma_str) + 1];
    strcpy(input, pw);
    strcat(input, sigma_str);

    // Computes the password-derived key
    element_t SK;
    element_init_Zr(SK, pairing);
    element_from_hash(SK, input, strlen(input));
    // element_printf("SK=%B\n", SK);

    element_t h_input;
    element_init_G1(h_input, pairing);
    element_pow_zn(h_input, R, SK);
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
    CryptoPP::FileSource fileSource("../Store/iv.bin", true, new CryptoPP::ArraySink(iv, sizeof(iv)));

    string plain;
    aes_CBC_Dec(cipher, ek_aes, iv, plain);
    cout << "The recovered plain is: " << plain << endl;
}