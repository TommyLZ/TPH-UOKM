#include "PublicParam.h"

#include <iostream>
#include <cstdlib>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <sys/timeb.h>
#include <cryptopp/integer.h>
#include <cryptopp/sha.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/osrng.h>
#include <cryptopp/aes.h>
#include <cryptopp/ccm.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/modes.h>
#include <cryptopp/base64.h>
#include <cryptopp/files.h>
#include <pbc/pbc.h>

using namespace std;
using namespace CryptoPP;

pairing_t pairing;
element_t P;

int n = 10; // Number of key servers
int t = 6; // Threshold

// System Initialization
void paramSetup()
{
    cout << "*********************************Parameter Setup************************************" << endl;
    // Set pbc param
    char param[1024];
    size_t count = fread(param, 1, 1024, stdin);
    if (!count)
        pbc_die("input error");

    // Initialize pairing
    pairing_init_set_buf(pairing, param, count);

    // Declare and initialize variables
    element_init_G1(P, pairing);
    element_random(P);

    cout << "System parameter setup finished!" << endl;
}

void save_key_to_file(element_t key, const char *filename)
{
    std::ofstream outfile(filename, std::ios::binary);
    size_t key_size = element_length_in_bytes(key);
    unsigned char key_bytes[key_size];
    element_to_bytes(key_bytes, key);
    outfile.write((char *)key_bytes, key_size);
    outfile.close();
}

void load_keys_from_file(element_t *keys, const char *filename)
{
    std::ifstream infile(filename, std::ios::binary);
    if (!infile)
    {
        cerr << "Error opening file for reading: " << filename << endl;
    }

    for (int i = 1; i <= t; i++)
    {
        size_t key_size = element_length_in_bytes(keys[i]);
        unsigned char *key_bytes = new unsigned char[key_size];
        infile.read(reinterpret_cast<char *>(key_bytes), key_size);
        element_from_bytes(keys[i], key_bytes);
        delete[] key_bytes;
    }

    infile.close();
}

void load_keyi_from_file(element_t &key, const char *filename)
{
    std::ifstream infile(filename, std::ios::binary);
    if (!infile)
    {
        cerr << "Error opening file for reading: " << filename << endl;
    }

    size_t key_size = element_length_in_bytes(key);
    unsigned char *key_bytes = new unsigned char[key_size];
    infile.read(reinterpret_cast<char *>(key_bytes), key_size);
    element_from_bytes(key, key_bytes);
    delete[] key_bytes;
}

void saveDataToBinFile(element_t R, element_t tau, const string &cipher, const char *fileName)
{
    ofstream file(fileName, ios::binary);
    if (!file.is_open())
    {
        cerr << "Error opening file for writing: " << fileName << endl;
        return;
    }

    // Write R to the file
    size_t R_size = element_length_in_bytes(R);
    unsigned char *R_bytes = new unsigned char[R_size];
    element_to_bytes(R_bytes, R);
    file.write(reinterpret_cast<const char *>(R_bytes), R_size);
    delete[] R_bytes;

    // Write tau to the file
    size_t tau_size = element_length_in_bytes(tau);
    unsigned char *tau_bytes = new unsigned char[tau_size];
    element_to_bytes(tau_bytes, tau);
    file.write(reinterpret_cast<const char *>(tau_bytes), tau_size);
    delete[] tau_bytes;

    // Write cipher to the file
    file.write(cipher.c_str(), cipher.size());

    file.close();
}

bool loadDataFromBinFile(element_t &R, element_t &tau, string &cipher, const char *fileName)
{
    ifstream file(fileName, ios::binary);
    if (!file.is_open())
    {
        cerr << "Error opening file for reading: " << fileName << endl;
        return false;
    }

    // Determine the size of R
    size_t R_size = element_length_in_bytes(R);
    unsigned char *R_bytes = new unsigned char[R_size];
    file.read(reinterpret_cast<char *>(R_bytes), R_size);

    // Determine the size of tau
    size_t tau_size = element_length_in_bytes(tau);
    unsigned char *tau_bytes = new unsigned char[tau_size];
    file.read(reinterpret_cast<char *>(tau_bytes), tau_size);

    // Read the cipher
    stringstream cipherStream;
    cipherStream << file.rdbuf();
    cipher = cipherStream.str();

    // Convert the read bytes back to elements
    element_from_bytes(R, R_bytes);
    element_from_bytes(tau, tau_bytes);

    delete[] R_bytes;
    delete[] tau_bytes;

    return true;
}

void secretShare(element_t &secret, element_t shares[], element_t coeff[])
{

    for (int i = 1; i <= n; i++)
    {
        element_init_Zr(shares[i], pairing);
        element_set(shares[i], secret);
    }

    for (int i = 1; i <= t - 1; i++)
    {
        element_init_Zr(coeff[i], pairing);
        element_random(coeff[i]);
    }

    for (int i = 1; i <= n; i++)
    {
        element_t x;
        element_init_Zr(x, pairing);
        element_set_si(x, i);

        for (int j = 1; j <= t - 1; j++)
        {
            element_t item;
            element_init_Zr(item, pairing);

            element_t power;
            element_init_Zr(power, pairing);
            element_set_si(power, j);

            element_pow_zn(item, x, power);
            element_mul(item, coeff[j], item);
            element_add(shares[i], shares[i], item);
        }

        // element_printf("share in the process is %B\n", shares[i]);
    }
}

void genLagrange(element_t lagrange[])
{
    for (int i = 1; i <= t; i++)
    {
        element_init_Zr(lagrange[i], pairing);
        element_set1(lagrange[i]);

        for (int j = 1; j <= t; j++)
        {
            if (i == j)
            {
                continue;
            }

            element_t numerator;
            element_init_Zr(numerator, pairing);
            element_set_si(numerator, j);

            element_t denominator;
            element_init_Zr(denominator, pairing);
            element_set_si(denominator, j - i);

            element_t denominator_invert;
            element_init_Zr(denominator_invert, pairing);
            element_invert(denominator_invert, denominator);

            element_t item;
            element_init_Zr(item, pairing);
            element_mul(item, numerator, denominator_invert);

            element_mul(lagrange[i], lagrange[i], item);
        }
    }
}

void secretRecover(element_t &recover_secret, element_t shares[])
{
    element_t lagrange[t + 1];

    genLagrange(lagrange);

    for (int i = 1; i <= t; i++)
    {
        element_t item;
        element_init_G1(item, pairing);
        element_pow_zn(item, shares[i], lagrange[i]);

        element_mul(recover_secret, recover_secret, item);
    }
}

void aes_CBC_Enc(const string &plain, const CryptoPP::byte *key, const CryptoPP::byte *iv, string &cipher)
{

    CBC_Mode<AES>::Encryption e;
    e.SetKeyWithIV(key, 16, iv);
    StringSource(plain, true,
                 new StreamTransformationFilter(e,
                                                new Base64Encoder(
                                                    new StringSink(cipher),
                                                    false // do not append a newline
                                                    )));

    // Pretty print cipher
    std::string encoded;
    HexEncoder encoder(new StringSink(encoded));
    encoder.Put((const CryptoPP::byte *)cipher.data(), cipher.size());
    encoder.MessageEnd();

    // cout << "plaintext: " << plain << endl;
    // cout << "cipher text: " << encoded << endl;

    // // Pretty print iv
    // encoded.clear();
    // StringSource(iv, 16, true,
    //              new HexEncoder(
    //                  new StringSink(encoded)) // HexEncoder
    // );                                        // StringSource
    // cout << "iv: " << encoded << endl;

    // // Pretty print key
    // encoded.clear();
    // StringSource(key, 16, true,
    //              new HexEncoder(
    //                  new StringSink(encoded)) // HexEncoder
    // );                                        // StringSource
    // cout << "key: " << encoded << endl;
}

void aes_CBC_Dec(const string &cipher, const CryptoPP::byte *key, const CryptoPP::byte *iv, string &plain)
{
    // // Pretty print cipher
    // std::string encoded;
    // HexEncoder encoder(new StringSink(encoded));
    // encoder.Put((const CryptoPP::byte *)cipher.data(), cipher.size());
    // encoder.MessageEnd();
    // std::cout << "cipher text: " << encoded << std::endl;

    // // Pretty print iv
    // encoded.clear();
    // StringSource(iv, 16, true,
    //              new HexEncoder(
    //                  new StringSink(encoded)) // HexEncoder
    // );                                        // StringSource
    // cout << "iv: " << encoded << endl;

    // // Pretty print key
    // encoded.clear();
    // StringSource(key, 16, true,
    //              new HexEncoder(
    //                  new StringSink(encoded)) // HexEncoder
    // );                                        // StringSource
    // cout << "key: " << encoded << endl;

    CBC_Mode<AES>::Decryption decryption;
    decryption.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);
    StringSource(cipher, true,
                 new Base64Decoder(
                     new StreamTransformationFilter(decryption,
                                                    new StringSink(plain))));
}