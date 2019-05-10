#ifndef CRYPTOQTSO_HASH_HPP
#define CRYPTOQTSO_HASH_HPP

#include "crossPlatformMacros.hpp"

#include "baseClassQtso/baseClassQt.hpp"

#include <QString>
#include <QByteArray>

#include <vector>
#include <string>


class EXPIMP_CRYPTOQTSO hasher_c : public baseClassQt_c
{
public:

    enum class hashType_ec
    {
        crc32c, whirlpool, SHA256, XXHASH64
    };
    enum class inputType_ec
    {
        string, file
    };
    //unsignedXbitInteger works for crc32c and xxhash because they fit in native integers types,
    //the others require *String outputs, they are too big to fit in a 64bit integer (C++ largest integer type on a 64-bit system)
    enum class outputType_ec
    {
        unsignedXbitInteger,
        decimalString,
        hexadecimalString,
        base64String
    };

    hasher_c() = delete;
    //ctor doesn't immediately generate the hash, call generateHash_f
    hasher_c(
            const inputType_ec inputType_par_con
            , const QString& input_par_con
            , const outputType_ec outputType_par_con
            , const hashType_ec hashType_par_con
    );

    //copy constructor
    hasher_c(const hasher_c& src) = delete;
    hasher_c& operator=(const hasher_c& src) = delete;
    //move ctor
    hasher_c(hasher_c&&) = delete;
    hasher_c& operator=(hasher_c&&) = delete;

    void generateHash_f();

    //for 64 bit hash (xxhash)
    uint64_t hash64BitNumberResult_f() const;
    bool hash64BitNumberResultSet_f() const;
    //for 32 bit hash (crc32c)
    uint32_t hash32BitNumberResult_f() const;
    bool hash32BitNumberResultSet_f() const;

    std::string hashStringResult_f() const;
    bool hashStringResultSet_f() const;

private:
    inputType_ec inputType_pri = inputType_ec::string;
    QString inputFilePath_pri;
    QByteArray inputString_pri;
    outputType_ec outputType_pri = outputType_ec::unsignedXbitInteger;
    hashType_ec hashType_pri = hashType_ec::crc32c;

    std::vector<uint_fast8_t> digest_pri;

	//for 64 bit hash (xxhash)
	uint64_t hash64BitNumberResult_pri = 0;
	bool hash64BitNumberResultSet_pri = false;

	//for 32 bit hash (crc32c)
	uint32_t hash32BitNumberResult_pri = 0;
	bool hash32BitNumberResultSet_pri = false;

	//ascii so it can be std::string, for everything
	std::string hashStringResult_pri;
	bool hashStringResultSet_pri = false;

    void hashFile_f();
    void hashString_f();
    void doEncode_f();
};



#endif // CRYPTOQTSO_HASH_HPP
