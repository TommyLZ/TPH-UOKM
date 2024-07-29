cmake_minimum_required(VERSION 3.0)

project(TPH-UOKM)

include_directories(Header)

add_executable(build main.cpp Source/PublicParam.cpp Source/KeyGen.cpp Source/Decryption.cpp  Source/Encryption.cpp Source/KeyServerUpdate.cpp Source/KeyShareUpdate.cpp Source/PasswordUpdate.cpp)

link_directories(/usr/local/lib /lib/x86_64-linux-gnu/ /usr/include)
target_link_libraries(build pbc gmp cryptopp)

set(CMAKE_BUILD_TYPE Debug)