#include "PasswordUpdate.h"
#include "PublicParam.h"

#include <iostream>
#include <pbc/pbc.h>

using namespace std;

extern pairing_t pairing;
extern element_t P;
extern int n, t;

void PasswordUpdate(char *pw, char* pw_new)
{
	cout << "***********************************PasswordUpdate Phase*********************************" << endl;

    element_t a_1, a_2;
    element_init_Zr(a_1, pairing);
    element_init_Zr(a_2, pairing);

    element_t a_1_inverse, a_2_inverse;
    element_init_Zr(a_1_inverse, pairing);
    element_init_Zr(a_2_inverse, pairing);
    element_invert(a_1_inverse, a_1);
    element_invert(a_2_inverse, a_2);

    element_t h_2_1;
    element_init_G1(h_2_1, pairing);
    element_from_hash(h_2_1, pw, strlen(pw));

    element_t h_2_2;
    element_init_G1(h_2_2, pairing);
    element_from_hash(h_2_2, pw_new, strlen(pw_new));

    element_t pw_hat, pw_new_hat;
    element_init_G1(pw_hat, pairing);
    element_init_G1(pw_new_hat, pairing);

    element_pow_zn(pw_hat, h_2_1, a_1);
    element_pow_zn(pw_new_hat, h_2_2, a_2);


    element_t shares[t + 1];
    for (int i = 1; i <= t; i++)
    {
        element_init_Zr(shares[i], pairing);
    }
    load_keys_from_file(shares, "../Store/shared_secret_key.bin");

    element_t sigma_eta_1[t + 1];
    for (int i = 1; i <= t; i++)
    {
        element_init_G1(sigma_eta_1[i], pairing);
        element_pow_zn(sigma_eta_1[i], pw_hat, shares[i]);
    }

    element_t sigma_eta_2[t + 1];
    for (int i = 1; i <= t; i++)
    {
        element_init_G1(sigma_eta_2[i], pairing);
        element_pow_zn(sigma_eta_2[i], pw_new_hat, shares[i]);
    }

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

        pairing_apply(tmp1, sigma_eta_1[i], P, pairing);
        pairing_apply(tmp2, pw_hat, shared_public_key[i], pairing);

        if (element_cmp(tmp1, tmp2))
        {
            cout << "Signature from each key server " << i << " fails!" << endl;
        }

        pairing_apply(tmp1, sigma_eta_2[i], P, pairing);
        pairing_apply(tmp2, pw_new_hat, shared_public_key[i], pairing);

        if (element_cmp(tmp1, tmp2))
        {
            cout << "Signature from each key server " << i << " fails!" << endl;
        }
    }

    element_t sum1, sum2;
    element_init_G1(sum1, pairing);
    element_init_G1(sum2, pairing);
    secretRecover(sum1, sigma_eta_1);
    secretRecover(sum2, sigma_eta_2);

    element_t sigma1, sigma2;
    element_init_G1(sigma1, pairing);
    element_init_G1(sigma2, pairing);
    element_pow_zn(sigma1, sum1, a_1_inverse);
    element_pow_zn(sigma2, sum2, a_2_inverse);

    element_t user_public_key;
    element_init_G1(user_public_key, pairing);
    load_keyi_from_file(user_public_key, "../Store/user_public_key.bin");

    element_t tmp1, tmp2;
    element_init_GT(tmp1, pairing);
    element_init_GT(tmp2, pairing);

    pairing_apply(tmp1, sigma1, P, pairing);
    pairing_apply(tmp2, h_2_1, user_public_key, pairing);

    if (!element_cmp(tmp1, tmp2))
    {
        cout << "Combined signature verifies!" << endl;
    }   

    pairing_apply(tmp1, sigma2, P, pairing);
    pairing_apply(tmp2, h_2_2, user_public_key, pairing);    

    if (!element_cmp(tmp1, tmp2))
    {
        cout << "Combined signature verifies!" << endl;
    }

    // Transform element_t to char*
    char sigma_str1[1024];
    element_snprint(sigma_str1, sizeof(sigma1), sigma1);
    char *input1 = new char[strlen(pw) + strlen(sigma_str1) + 1];
    strcpy(input1, pw);
    strcat(input1, sigma_str1);

    // Transform element_t to char*
    char sigma_str2[1024];
    element_snprint(sigma_str2, sizeof(sigma2), sigma2);
    char *input2 = new char[strlen(pw_new) + strlen(sigma_str2) + 1];
    strcpy(input2, pw_new);
    strcat(input2, sigma_str2);

    // Computes the password-derived key
    element_t SK_1;
    element_init_Zr(SK_1, pairing);
    element_from_hash(SK_1, input1, strlen(input1));
    element_printf("SK=%B\n", SK_1);

    // Computes the password-derived key
    element_t SK_2;
    element_init_Zr(SK_2, pairing);
    element_from_hash(SK_2, input2, strlen(input1));
    element_printf("SK=%B\n", SK_2);

    // Computes the public key
    element_t PK;
    element_init_G1(PK, pairing);
    element_pow_zn(PK, P, SK_2);
    element_printf("P=%B\n", P);
    element_printf("PK=%B\n", PK);

    // Store
    save_key_to_file(PK, "../Store/PK.bin");

    element_t delta;
    element_init_Zr(delta, pairing);
    
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

    element_t SK_2_inverse;
    element_init_Zr(SK_2_inverse, pairing);
    element_invert(SK_2_inverse, SK_2);
    element_mul(delta, SK_1, SK_2_inverse);

    for (int i = 0; i< 1000; i++){
         element_pow_zn(R, R, delta);
    }
    saveDataToBinFile(R, tau, cipher, "../Store/CS_store.bin");
}