# criptoQtso
C++ library to hash string or files in several types of hash (crc32c, xxhash, whirlpool and SHA256), Qt version, Qt solves the big issue of reading UTF8 filenames correctly in windows, mingw32 ifstream can't.

Compilation
-----------
Requires Qt library and https://github.com/jouven/criptoso

Run (in fileHashQtso source directory or pointing to it):

    qmake

and then:

    make
