#include <iostream>
#include <NTL/ZZ.h>
#include <NTL/mat_ZZ.h>
#include <NTL/mat_lzz_p.h>

using namespace NTL;
using namespace std;

void FillRandom(Mat<ZZ_p> &A)
{
    long n = A.NumRows();
    long m = A.NumCols();

    for (long i = 0; i < n; i++)
    {
        for (long j = 0; j < m; j++)
        {
            random(A[i][j]);
            // A[i][j]= pow(j + 1, i);
        }
    }
}

void FillRandom1(Mat<ZZ_p> &A)
{
    long n = A.NumRows();
    long m = A.NumCols();

    long r;
    long choice = RandomBnd(5);

    if (choice == 0 || n == 0)
    {
        r = 0;
    }
    else if (choice == 1)
    {
        r = min(n, 1 + RandomBnd(10));
    }
    else
    {
        r = 1 + RandomBnd(n);
    }

    Mat<ZZ_p> B, C;

    B.SetDims(n, n);
    FillRandom(B);

    C.SetDims(n, m);
    for (long i = 0; i < r; i++)
        for (long j = 0; j < m; j++)
            random(C[i][j]);

    mul(A, B, C);
}

long old_gauss(mat_ZZ_p &M, long w)
{
    using NTL_NAMESPACE::negate;
    long k, l;
    long i, j;
    long pos;
    ZZ_p t1, t2, t3;
    ZZ_p *x, *y;

    long n = M.NumRows();
    long m = M.NumCols();

    if (w < 0 || w > m)
        LogicError("gauss: bad args");

    ZZ p = ZZ_p::modulus();
    ZZ pinv;
    InvMod(pinv, p, to_ZZ(1) << 256); // Calculate the modular inverse
    ZZ T1, T2;

    l = 0;
    for (k = 0; k < w && l < n; k++)
    {

        pos = -1;
        for (i = l; i < n; i++)
        {
            if (!IsZero(M[i][k]))
            {
                pos = i;
                break;
            }
        }

        if (pos != -1)
        {
            swap(M[pos], M[l]);

            inv(t3, M[l][k]);
            negate(t3, t3);

            for (i = l + 1; i < n; i++)
            {
                // M[i] = M[i] + M[l]*M[i,k]*t3

                mul(t1, M[i][k], t3);

                T1 = rep(t1);
                MulMod(T1, p, pinv);

                clear(M[i][k]);

                x = M[i].elts() + (k + 1);
                y = M[l].elts() + (k + 1);

                for (j = k + 1; j < m; j++, x++, y++)
                {
                    // *x = *x + (*y)*t1
                    MulMod(T2, rep(*y), T1);
                    T2 = AddMod(T2, rep(*x), p);
                    (*x).LoopHole() = T2;
                }
            }

            l++;
        }
    }

    return l;
}

long old_gauss(mat_ZZ_p &M)
{
    return old_gauss(M, M.NumCols());
}

void old_image(mat_ZZ_p &X, const mat_ZZ_p &A)
{
    mat_ZZ_p M;
    M = A;
    long r = old_gauss(M);
    M.SetDims(r, M.NumCols());
    X = M;
}
  
int main()
{
    ZZ seed;
    RandomLen(seed, 30);
    SetSeed(seed);

    long n = 10;
    long t = 6;

    ZZ mod;
    // RandomPrime(mod, 256); // Generate a random 256-bit prime number
    mod = to_ZZ("1461501637330902918203684757158419293741609123839");
    ZZ_p::init(mod);

    // 1461501637330902918203684757158419293741609123839

    cout << "mod=: " << mod << endl;

    Mat<ZZ_p> vandermonde;
    vandermonde.SetDims(n, t-1);
    // FillRandom1(vandermonde);

    for (long i = 0; i < n; i++)
    {
        for (long j = 0; j < t-1; j++)
        {
            // random(A[i][j]);
            vandermonde[i][j]= pow(i+1, j+1);
        }
    }


    Mat<ZZ_p> im, im1, kernelMatrix;

    old_image(im, vandermonde);
    image(im1, vandermonde);
    kernel(kernelMatrix, vandermonde);

    // Display the Vandermonde matrix
    std::cout << "Vandermonde matrix:" << std::endl;
    std::cout << vandermonde << std::endl;

    // Display the kernel matrix
    std::cout << "Kernel matrix:" << std::endl;
    std::cout << kernelMatrix << std::endl;

    // Display the multiplication
    std::cout << "Kernel matrix * vandermonde:" << std::endl;
    std::cout << kernelMatrix * vandermonde << std::endl;

    if (!IsZero(kernelMatrix * vandermonde)){
        cout << "The multiplication is not zero!" << endl;
    }

    return 0;
}
