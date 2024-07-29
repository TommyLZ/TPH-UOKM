#include "KeyServerUpdate.h"
#include "PublicParam.h"

#include <iostream>
#include <pbc/pbc.h>
#include <cmath>

using namespace std;

extern pairing_t pairing;
extern element_t P;
extern int n, t;

void KeyServerUpdate(char *pw)
{

    cout << "***********************************KeyServerUpdate Phase*********************************" << endl;

    element_t coeff[t + 1][t];
    for (int i = 1; i <= t; i++)
    {
        for (int j = 1; j <= t - 1; j++)
        {
            element_init_Zr(coeff[i][j], pairing);
            element_random(coeff[i][j]);
        }
    }

    element_t coeff_public_key[t + 1][t];
    for (int i = 1; i <= t; i++)
    {
        for (int j = 1; j <= t - 1; j++)
        {
            element_init_G1(coeff_public_key[i][j], pairing);
            element_pow_zn(coeff_public_key[i][j], P, coeff[i][j]);
        }
    }

    element_t shares[t + 1];
    for (int i = 1; i <= t; i++)
    {
        element_init_Zr(shares[i], pairing);
    }
    load_keys_from_file(shares, "../Store/shared_secret_key.bin");

    element_t new_shares[t + 1][n + 1];
    for (int i = 1; i <= t; i++)
    {
        for (int j = 1; j <= n; j++)
        {
            element_init_Zr(new_shares[i][j], pairing);
        }

        secretShare(shares[i], new_shares[i], coeff[i]);
    }

    element_t shared_public_key[t + 1];
    for (int i = 1; i <= t; i++)
    {
        element_init_G1(shared_public_key[i], pairing);
    }
    load_keys_from_file(shared_public_key, "../Store/shared_public_key.bin");

    element_t lagrange[t + 1];
    genLagrange(lagrange);

    element_t user_public_key;
    element_init_G1(user_public_key, pairing);
    load_keyi_from_file(user_public_key, "../Store/user_public_key.bin");

    for (int j = 1; j <= n; j++)
    {
        element_t right_2;
        element_init_G1(right_2, pairing);

        for (int ik = 1; ik <= t; ik++)
        {
            element_t right;
            element_init_G1(right, pairing);
            element_set(right, shared_public_key[ik]);

            for (int k = 1; k <= t - 1; k++)
            {
                int power;
                power = pow(j, k);

                element_t j_pow_t;
                element_init_Zr(j_pow_t, pairing);
                element_set_si(j_pow_t, power);

                element_t item;
                element_init_G1(item, pairing);
                element_pow_zn(item, coeff_public_key[ik][k], j_pow_t);

                element_mul(right, right, item);
            }

            element_t left;
            element_init_G1(left, pairing);
            element_pow_zn(left, P, new_shares[ik][j]);

            // element_printf("left=%B \n", left);
            // element_printf("right=%B \n", right);

            if (!element_cmp(left, right))
            {
                cout << "succeed" << endl;
            }

            element_t item2;
            element_init_G1(item2, pairing);
            element_pow_zn(item2, shared_public_key[ik], lagrange[ik]);

            element_mul(right_2, right_2, item2);
        }

        if (element_cmp(user_public_key, right_2))
        {
            cout << "fails" << endl;
        }
    }

    element_t renewed_share[n + 1]; 
    element_t renewed_share_public_key[n + 1];
    for (int j = 1; j <= n; j++)
    {
        element_init_Zr(renewed_share[j], pairing);
        element_init_G1(renewed_share_public_key[j], pairing);

        for (int ik = 1; ik <= t; ik++)
        {
            element_t item;
            element_init_Zr(item, pairing);
            element_mul(item, lagrange[ik], new_shares[ik][j]);

            element_add(renewed_share[j], renewed_share[j], item);
        }

        element_pow_zn(renewed_share_public_key[j], P, renewed_share[j]);
    }
}