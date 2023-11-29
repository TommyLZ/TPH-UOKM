#include "PublicParam.h"
#include "KeyShareUpdate.h"

#include <iostream>
#include <pbc/pbc.h>
using namespace std;

extern pairing_t pairing;
extern element_t P;
extern int t, n;

void KeyShareUpdate(char *pw, char *id)
{
    cout << "***********************************KeyShareUpdate Phase*********************************" << endl;

    // In this test case, we simulate the process of one key server updating the share of m users.

    int m = 10;

    const char *matrix_H[t - 1][n] = {
        {"1461501637330902918203684757158419293741609123139", "1575", "1461501637330902918203684757158419293741609122039", "1050", "1461501637330902918203684757158419293741609123587", "0", "0", "0", "0", "1"},
        {"1461501637330902918203684757158419293741609123524", "720", "1461501637330902918203684757158419293741609122999", "504", "1461501637330902918203684757158419293741609123713", "0", "0", "0", "1", "0"},
        {"1461501637330902918203684757158419293741609123719", "280", "1461501637330902918203684757158419293741609123503", "210", "1461501637330902918203684757158419293741609123783", "0", "0", "1", "0", "0"},
        {"1461501637330902918203684757158419293741609123804", "84", "1461501637330902918203684757158419293741609123734", "70", "1461501637330902918203684757158419293741609123818", "0", "1", "0", "0", "0"},
        {"1461501637330902918203684757158419293741609123833", "15", "1461501637330902918203684757158419293741609123819", "15", "1461501637330902918203684757158419293741609123833", "1", "0", "0", "0", "0"}};

    element_t H[t - 1][n];
    for (int i = 0; i < t - 1; i++)
    {
        for (int j = 0; j < n; j++)
        {
            element_init_Zr(H[i][j], pairing);
            element_set_str(H[i][j], matrix_H[i][j], 10);
        }
    }

    const char *matrix_A[n][t - 1] = {
        {"1", "1", "1", "1", "1"},
        {"2", "4", "8", "16", "32"},
        {"3", "9", "27", "81", "243"},
        {"4", "16", "64", "256", "1024"},
        {"5", "25", "125", "625", "3125"},
        {"6", "36", "216", "1296", "7776"},
        {"7", "49", "343", "2401", "16807"},
        {"8", "64", "512", "4096", "32768"},
        {"9", "81", "729", "6561", "59049"},
        {"10", "100", "1000", "10000", "100000"}};

    element_t A[n][t - 1];
    for (int i = 0; i < n; i++)
    {
        for (int j = 0; j < t - 1; j++)
        {
            element_init_Zr(A[i][j], pairing);
            element_set_str(A[i][j], matrix_A[i][j], 10);
        }
    }

    // H * A: Verify the correctness of the check matrix
    element_t res[t - 1][t - 1];
    for (int i = 0; i < t - 1; i++)
    {
        element_t sum;
        element_init_Zr(sum, pairing);

        for (int k = 0; k < t - 1; k++)
        {
            element_t item;
            element_init_Zr(item, pairing);

            for (int j = 0; j < n; j++)
            {
                element_mul(item, H[i][j], A[j][k]);
                element_add(sum, sum, item);
            }

            element_init_Zr(res[i][k], pairing);
            element_set(res[i][k], sum);
            element_set0(sum);
        }
    }
    element_printf("\n");

    for (int i = 0; i < t - 1; i++)
    {
        for (int j = 0; j < t - 1; j++)
        {
            element_printf("%B ", res[i][j]);
        }
        element_printf("\n");
    }
    element_printf("\n");

    // Randomly choosing the coefficient of r_i(x)
    const char *vector_b[t - 1][1] = {
        {"112312312"},
        {"1241232334124112341"},
        {"141241241212412"},
        {"14141241241"},
        {"141241241241"}};

    element_t b[t - 1][1];
    for (int i = 0; i < t - 1; i++)
    {
        for (int j = 0; j < 1; j++)
        {
            element_init_Zr(b[i][j], pairing);
            element_set_str(b[i][j], vector_b[i][j], 10);
        }
    }

    // Calculate r_i(1) to r_i(n)
    element_t z1[n][1];
    for (int i = 0; i < n; i++)
    {
        for (int j = 0; j < 1; j++)
        {
            element_t sum;
            element_init_Zr(sum, pairing);

            for (int k = 0; k < t - 1; k++)
            {
                element_t item;
                element_init_Zr(item, pairing);

                element_mul(item, A[i][k], b[k][j]);
                element_add(sum, sum, item);
            }
            element_init_Zr(z1[i][j], pairing);
            element_set(z1[i][j], sum);
            element_set0(sum);
        }
    }

    // Randomly choosing the coefficient of f_eta_i(x), 1 <= eta <= m
    element_t c[m][t - 1][1];
    for (int k = 0; k < m; k++)
    {
        for (int i = 0; i < t - 1; i++)
        {
            for (int j = 0; j < 1; j++)
            {
                element_init_Zr(c[k][i][j], pairing);
                element_random(c[k][i][j]);
            }
        }
    }

    // Compute f_i(x)
    element_t z2[m][n][1];
    for (int eta = 0; eta < m; eta++)
    {
        for (int i = 0; i < n; i++)
        {
            for (int j = 0; j < 1; j++)
            {
                element_t sum;
                element_init_Zr(sum, pairing);

                for (int k = 0; k < 5; k++)
                {
                    element_t item;
                    element_init_Zr(item, pairing);

                    element_mul(item, A[i][k], c[eta][k][j]);
                    element_add(sum, sum, item);
                }

                element_init_Zr(z2[eta][i][j], pairing);
                element_set(z2[eta][i][j], sum);
                element_set0(sum);
            }
        }
    }

    // Compute C_i = r_i + z1p + z2P + ... +zmP
    element_t C[n][1];
    for (int i = 0; i < n; i++)
    {
        element_init_G1(C[i][0], pairing);

        element_t power;
        element_init_G1(power, pairing);
        element_pow_zn(power, P, z1[i][0]);

        element_set(C[i][0], power);

        for (int j = 0; j < m; j++)
        {
            element_t item;
            element_init_G1(item, pairing);
            element_pow_zn(item, P, z2[j][i][0]);

            element_mul(C[i][0], C[i][0], item);
            element_set0(item);
        }
    }

    // Randomly choosing v
    element_t v[1][t - 1];
    for (int i = 0; i < t - 1; i++)
    {
        element_init_Zr(v[0][i], pairing);
        element_random(v[0][i]);
    }

    // Calculate u = v*H
    element_t u[1][n];
    for (int i = 0; i < 1; i++)
    {
        for (int j = 0; j < n; j++)
        {
            element_t sum;
            element_init_Zr(sum, pairing);

            for (int k = 0; k < t - 1; k++)
            {
                element_t item;
                element_init_Zr(item, pairing);

                element_mul(item, v[i][k], H[k][j]);
                element_add(sum, sum, item);
            }
            element_init_Zr(u[i][j], pairing);
            element_set(u[i][j], sum);
            element_set0(sum);
        }
    }

    // Verify u* C = 0
    element_t res_3;
    for (int i = 0; i < 1; i++)
    {
        for (int j = 0; j < 1; j++)
        {
            element_t sum;
            element_init_Zr(sum, pairing);

            for (int k = 0; k < n; k++)
            {
                element_t item;
                element_init_Zr(item, pairing);

                element_mul(item, u[i][k], C[k][j]);
                element_add(sum, sum, item);
            }
            element_init_Zr(res_3, pairing);
            element_set(res_3, sum);
            element_set0(sum);
        }
    }

    element_printf("The linearity test result is %B.\n", res_3);

    element_t shares[n + 1];
    for (int i = 1; i <= n; i++)
    {
        element_init_Zr(shares[i], pairing);
    }
    load_keys_from_file(shares, "../Store/shared_secret_key.bin");

    // Update the share.
    // We simulate computational cost of update m shares by updating a share m times.
    element_t newshare;
    element_init_Zr(newshare, pairing);
    element_set(newshare, shares[1]);

    for (int i = 1; i <=m ; i++)
    {
        for (int j = 0; j < n; j++)
        {
            element_add(newshare, newshare, z2[1][j][0]);
        }

        element_set(newshare, shares[1]);
    }

    element_t newshare_public;
    element_init_G1(newshare, pairing);
    element_pow_zn(newshare_public, P, newshare);

    cout << "***********************************KeyShareUpdate Phase Finished*********************************" << endl;
}