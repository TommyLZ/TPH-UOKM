#include "PublicParam.h"
#include "KeyShareUpdate.h"

#include <iostream>
using namespace std;

extern pairing_t pairing;
extern element_t P;
extern int t, n;

void KeyShareUpdate(char *pw, char *id)
{

    cout << "***********************************KeyShareUpdate Phase*********************************" << endl;

    int m = 1; // Number of the user.

    element_t b[t][n + 1];
    element_t c[m + 1][t][n + 1];

    for (int i = 1; i <= t - 1; i++)
    {
        for (int j = 1; j <= n; j++)
        {
            element_init_Zr(b[i][j], pairing);
            element_random(b[i][j]);
        }
    }

    for (int i = 1; i <= m; i++)
    {
        for (int j = 1; j <= t - 1; j++)
        {
            for (int k = 1; k <= n; k++)
            {
                element_init_Zr(c[i][j][k], pairing);
                element_random(c[i][j][k]);
            }
        }
    }

    // Compute r
    element_t r[n + 1][n + 1];
    for (int j = 1; j <= n; ++j)
    {
        for (int i = 1; i <= n; i++)
        {
            element_init_Zr(r[j][i], pairing);

            for (int k = 1; k <= t - 1; k++)
            {
                element_t jj, tt;
                element_init_Zr(jj, pairing);
                element_init_Zr(tt, pairing);
                element_set_si(jj, j);
                element_set_si(tt, k);

                element_t power;
                element_init_Zr(power, pairing);
                element_pow_zn(power, jj, tt);

                element_t item;
                element_init_Zr(item, pairing);
                element_mul(item, b[k][i], power);
                element_add(r[j][i], r[j][i], item);
            }
        }
    }

    // Compute z
    element_t z[m + 1][n + 1][n + 1];
    for (int eta = 1; eta <= m; eta++)
    {
        for (int j = 1; j <= n; j++)
        {
            for (int i = 1; i <= n; i++)
            {
                element_init_Zr(z[eta][j][i], pairing);

                for (int k = 1; k <= t - 1; k++)
                {
                    element_t jj, tt;
                    element_init_Zr(jj, pairing);
                    element_init_Zr(tt, pairing);
                    element_set_si(jj, j);
                    element_set_si(tt, k);

                    element_t power;
                    element_init_Zr(power, pairing);
                    element_pow_zn(power, jj, tt);

                    element_t item;
                    element_init_Zr(item, pairing);
                    element_mul(item, c[eta][k][i], power);

                    // element_printf("item of z =%B\n", item);
                    element_add(z[eta][j][i], z[eta][j][i], item);
                    // element_printf("z[eta][j][i]=%B\n", z[eta][j][i]);
                }
            }
        }
    }

    element_t id_hash;
    element_init_G1(id_hash, pairing);
    element_from_hash(id_hash, id, strlen(id));

    element_t C[n + 1][n + 1];
    for (int j = 1; j <= n; j++)
    {
        for (int i = 1; i <= n; i++)
        {
            element_init_G1(C[j][i], pairing);

            element_t r_mul_P;
            element_init_G1(r_mul_P, pairing);
            element_pow_zn(r_mul_P, P, r[j][i]);

            element_set(C[j][i], r_mul_P);

            for (int eta = 1; eta <= m; eta++)
            {
                element_t item;
                element_init_G1(item, pairing);
                element_pow_zn(item, id_hash, z[eta][j][i]);

                element_mul(C[j][i], C[j][i], item);
            }
        }
    }

    // Parity Matrix (n= 10, t = 6)
    // H = [[1461501637330902918203684757158419293741609123139 1575 1461501637330902918203684757158419293741609122039 1050 1461501637330902918203684757158419293741609123587 0 0 0 0 1]
    // [1461501637330902918203684757158419293741609123524 720 1461501637330902918203684757158419293741609122999 504 1461501637330902918203684757158419293741609123713 0 0 0 1 0]
    // [1461501637330902918203684757158419293741609123719 280 1461501637330902918203684757158419293741609123503 210 1461501637330902918203684757158419293741609123783 0 0 1 0 0]
    // [1461501637330902918203684757158419293741609123804 84 1461501637330902918203684757158419293741609123734 70 1461501637330902918203684757158419293741609123818 0 1 0 0 0]
    // [1461501637330902918203684757158419293741609123833 15 1461501637330902918203684757158419293741609123819 15 1461501637330902918203684757158419293741609123833 1 0 0 0 0]
    // ]

    // const char *values[5][10] = {
    //     {"1461501637330902918203684757158419293741609123139", "1575", "1461501637330902918203684757158419293741609122039", "1050", "1461501637330902918203684757158419293741609123587", "0", "0", "0", "0", "1"},
    //     {"1461501637330902918203684757158419293741609123524", "720", "1461501637330902918203684757158419293741609122999", "504", "1461501637330902918203684757158419293741609123713", "0", "0", "0", "1", "0"},
    //     {"1461501637330902918203684757158419293741609123719", "280", "1461501637330902918203684757158419293741609123503", "210", "1461501637330902918203684757158419293741609123783", "0", "0", "1", "0", "0"},
    //     {"1461501637330902918203684757158419293741609123804", "84", "1461501637330902918203684757158419293741609123734", "70", "1461501637330902918203684757158419293741609123818", "0", "1", "0", "0", "0"},
    //     {"1461501637330902918203684757158419293741609123833", "15", "1461501637330902918203684757158419293741609123819", "15", "1461501637330902918203684757158419293741609123833", "1", "0", "0", "0", "0"}};

    // element_t H[5][10];
    // for (int i = 0; i < 5; i++)
    // {
    //     for (int j = 0; j < 10; j++)
    //     {
    //         element_init_Zr(H[i][j], pairing);
    //         element_set_str(H[i][j], values[i][j], 10);
    //     }
    // }

    // element_t v[5];
    // for (int i = 0; i < 5; i++)
    // {
    //     element_init_Zr(v[i], pairing);
    //     element_random(v[i]);
    // }

    // element_t u[10];
    // for (int i = 0; i < 10; i++)
    // {
    //     element_init_Zr(u[i], pairing);
    //     element_set0(u[i]);

    //     for (int j = 0; j < 5; j++)
    //     {
    //         element_t item;
    //         element_init_Zr(item, pairing);
    //         element_mul(item, v[j], H[j][i]);

    //         element_add(u[i], u[i], item);
    //     }

    //     // element_printf("the u[i] is %B\n", u[i]);
    // }

    // element_t res;
    // element_init_G1(res, pairing);
    // element_set0(res);

    // element_t a;
    // element_init_G1(a, pairing);
    // element_random(a);

    // for (int i = 0; i < 10; i++)
    // {
    //     for (int j = 1; j <= n; j++)
    //     {
    //         element_t item;
    //         element_init_G1(item, pairing);
    //         element_mul(item, u[j - 1], C[i+1][j]);
    //         // element_printf("a = %B\n", a);
    //         // element_printf("the item = %B\n", item);
    //         // element_printf("C[i+1][j]=%B\n", C[i + 1][j]);
    //         // element_printf("u[j - 1]=%B\n", u[j - 1]);
    //         element_add(res, res, item);
    //     }
    //     element_printf("The check result is %B\n", res);
    // }

    // element_t shares[n + 1];
    // for (int i = 1; i <= n; i++)
    // {
    //     element_init_Zr(shares[i], pairing);
    // }
    // load_keys_from_file(shares, "../Store/shared_secret_key.bin");

    // element_t new_share[m + 1][n + 1];
    // element_t new_share_public_key[m + 1][n + 1];
    // for (int eta = 1; eta <= m; eta++)
    // {
    //     for (int i = 1; i <= n; i++)
    //     {
    //         element_init_Zr(new_share[eta][i], pairing);
    //         element_set(new_share[eta][i], shares[i]);
    //         element_init_Zr(new_share_public_key[eta][i], pairing);

    //         for (int j = 1; j <= n; j++)
    //         {
    //             element_add(new_share[eta][i], new_share[eta][i], z[eta][i][j]);
    //         }

    //         element_pow_zn(new_share_public_key[eta][i], P, new_share[eta][i]);
    //     }
    // }
}