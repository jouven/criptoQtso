#ifndef CRIPTOQTSO_HASH_HPP
#define CRIPTOQTSO_HASH_HPP

#include "baseClassQtso/baseClassQt.hpp"

#include "config.h"

#include <QString>

#include <vector>
#include <string>

namespace eines
{

class hasher_c : public baseClassQt_c
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
    //number works for crc32c and xxhash because it outputs to hashNumberResult_pri (a 64bit unsigned integer)
    //the others need hex or base64, they are too big to fit in a 64bit integer
    enum class outputType_ec
    {
        number,
        hex,
        base64
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

    uint_fast64_t hashNumberResult_f() const;
    bool hashNumberResultSet_f() const;

    std::string hashStringResult_f() const;
    bool hashStringResultSet_f() const;

private:
    inputType_ec inputType_pri = inputType_ec::string;
    QString input_pri;
    outputType_ec outputType_pri = outputType_ec::number;
    hashType_ec hashType_pri = hashType_ec::crc32c;

    std::vector<byte> digest_pri;

	//for crc32c or xxhash
	uint_fast64_t hashNumberResult_pri = 0;
	bool hashNumberResultSet_pri = false;
	//ascii so it can be std::string
	std::string hashStringResult_pri;
	bool hashStringResultSet_pri = false;

    void hashFile_f();
    void hashString_f();
    void doEncode_f();
};

}


#endif // CRIPTOQTSO_HASH_HPP
