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

    // Data decryption
    Decryption(pw);

    //Key Share Update
    KeyShareUpdate(pw, id);

    // Key Server update    
    KeyServerUpdate(pw);

    // Password update
    PasswordUpdate(pw, pw_new);

    return 0;
}