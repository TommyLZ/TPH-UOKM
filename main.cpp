#include "PublicParam.h"
#include "Encryption.h"
#include "Decryption.h"
#include "KeyServerUpdate.h"
#include "KeyShareUpdate.h"
#include "PasswordUpdate.h"
#include "KeyGen.h"

#include <iostream>
#include <chrono>

using namespace std;

int main()
{
    char id[] = "Jean Valjean";
    char pw[] = "f4520tommy";
    char pw_new[] = "newpassword";

    // Set the system parameter
    paramSetup();

    // Key generation
    KeyGen(pw);

    // Data encryption
    Encryption(pw);

    // // Data decryption
    int iteration = 10;
    double totalTime = 0.0;
    // for (int i = 0; i < iteration; i++)
    // {
    //     auto start = chrono::high_resolution_clock::now();
    //     Decryption(pw);
    //     auto end = chrono::high_resolution_clock::now();
    //     chrono::duration<double> duration= end - start;

    //     totalTime += duration.count();
    // }

    // cout << "The average running time of the decryption phase: " << totalTime/iteration << "seconds" << endl;

    // // Key Share Update
    // for (int i = 0; i < iteration; i++)
    // {
    //     auto start = chrono::high_resolution_clock::now();
    //     KeyShareUpdate(pw, id);
    //     auto end = chrono::high_resolution_clock::now();
    //     chrono::duration<double> duration= end - start;

    //     totalTime += duration.count();
    // }
    // cout << "The average running time of the key share update phase: " << totalTime/iteration << "seconds" << endl;

    // // Key Server update
    for (int i = 0; i < iteration; i++)
    {
        auto start = chrono::high_resolution_clock::now();
        KeyServerUpdate(pw);
        auto end = chrono::high_resolution_clock::now();
        chrono::duration<double> duration = end - start;

        totalTime += duration.count();
    }
    cout << "The average running time of the key server update phase: " << totalTime / iteration << "seconds" << endl;

        // // Password update

        // for (int i = 0; i < iteration; i++)
        // {
        //     auto start = chrono::high_resolution_clock::now();
        //     PasswordUpdate(pw, pw_new);
        //     auto end = chrono::high_resolution_clock::now();
        //     chrono::duration<double> duration = end - start;

        //     totalTime += duration.count();
        // }
        // cout << "The average running time of the password update phase: " << totalTime / iteration << "seconds" << endl;

        return 0;
    }

    //
    // Registration(psw_u, id_u);
