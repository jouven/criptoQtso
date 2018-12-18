# cryptoQtso
C++ library to hash string or files in several types of hash (crc32c, xxhash, whirlpool and SHA256), Qt version, Qt solves the big issue of reading UTF8 filenames correctly in windows, mingw32 ifstream can't.

Compilation
-----------
Requires:

Qt library

https://github.com/jouven/baseClassQtso

https://github.com/jouven/crc32cso

https://github.com/Cyan4973/xxHash in library form

https://cryptopp.com/

Check .pro file to know what library names expect (or to change them).

Run (in cryptoQtso source directory or pointing to it):

    qmake

and then:

    make
