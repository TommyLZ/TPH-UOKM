# TPH-UOKM

This repository contains a reference implementation of TPH-UOKM: Threshold Password-Hardening Updatable Oblivious Key Management. 

WARNING: This is an academic prototype, and should not be used in applications without code review.

## How to run
### Dependencies
- Crypto++ 8.6.0
- PBC 0.5.14
- NTL 11.5.1
### Running the repo
Clone this repo. Make sure `g++` and `cmake` have been installed. (Linux) \
Build and run the experiment locally.
```
cd Build
cmake ..
make
./build < ../Param/a.param
```