#include "hashQt.hpp"
//crc32c
#include "crc32cso/crc32c.hpp"
//xxhash
#include "xxhashso/xxhash.h"
//cryptopp
#include <hex.h>
#include <sha.h>
#include <whrlpool.h>
#include <base64.h>
#include <integer.h>

#ifdef DEBUGJOUVEN
#include "comuso/loggingMacros.hpp"
#ifndef __ANDROID__
#include "backwardSTso/backward.hpp"
#endif
#endif

#include <QFile>

#include <cstdint>
#include <vector>

#if (CRYPTOPP_VERSION >= 600) && (__cplusplus >= 201103L)
    using byte = CryptoPP::byte;
#else
    typedef unsigned char byte;
#endif

namespace eines
{

template <typename T>
std::vector<byte> intToByte_f(
        const T integer_par_con
)
{
    std::vector<byte> byteVector(sizeof(T));
    #ifdef DEBUGJOUVEN
                    //std::cout << DEBUGDATETIME << "sizeof(uint_fast64_t) " << sizeof(uint_fast64_t) << std::endl;
    #endif

    std::copy(static_cast<const byte*>(static_cast<const void*>(&integer_par_con)),
              static_cast<const byte*>(static_cast<const void*>(&integer_par_con)) + sizeof(T),
              &byteVector[0]);
#if BYTE_ORDER == LITTLE_ENDIAN
    std::reverse(byteVector.begin(), byteVector.end());
#endif
//#if byteVector == BYTE_ORDER
//    for (std::size_t i = 0; i < sizeof(uint_fast64_t); ++i)
//        byteVector[(sizeof(uint_fast64_t) - 1) - i] = (integer_par_con >> (i * 8));
//#else
//    for (std::size_t i = 0; i < sizeof(uint_fast64_t); ++i)
//        byteVector[i] = (integer_par_con >> (i * 8));
//#endif

	return byteVector;
}

void hasher_c::generateHash_f()
{
	//#ifdef DEBUGJOUVEN
	//			DEBUGSOURCEBEGIN
	//#endif
	    //#ifdef DEBUGJOUVEN
	    //				std::cout << DEBUGDATETIME << "_input.size() > 0\n";
	    //#endif
	switch (inputType_pri)
	{
	case inputType_ec::file:
	{
		if (inputFilePath_pri.isEmpty())
		{
			appendError_f("Empty filename");
		}
		else
		{
			hashFile_f();
		}
	}
		break;
	case inputType_ec::string:
	{
		if (inputString_pri.isEmpty())
		{
			appendError_f("Empty string");
		}
		else
		{
			hashString_f();
		}
	}
		break;
	};

	doEncode_f();
	//#ifdef DEBUGJOUVEN
	//			DEBUGSOURCEEND
	//#endif
}

uint64_t hasher_c::hash64BitNumberResult_f() const
{
	return hash64BitNumberResult_pri;
}

uint32_t hasher_c::hash32BitNumberResult_f() const
{
	return hash32BitNumberResult_pri;
}

bool hasher_c::hash64BitNumberResultSet_f() const
{
	return hash64BitNumberResultSet_pri;
}

bool hasher_c::hash32BitNumberResultSet_f() const
{
	return hash32BitNumberResultSet_pri;
}

std::string hasher_c::hashStringResult_f() const
{
	return hashStringResult_pri;
}

bool hasher_c::hashStringResultSet_f() const
{
	return hashStringResultSet_pri;
}

void hasher_c::hashFile_f()
{
	//#ifdef DEBUGJOUVEN
	//			DEBUGSOURCEBEGIN
	//#endif

	QFile inFile(inputFilePath_pri);
	if (inFile.open(QIODevice::ReadOnly))
	{
		qint64 readSize(0);
		std::vector<char> buffer;
		//32K
		constexpr int_fast64_t smallBuffer(32768);
		//2MB
		constexpr int_fast64_t bigBuffer(smallBuffer * 64);
		//10MB
		constexpr int_fast64_t bigBufferThreshold(bigBuffer * 5);
		if (inFile.size() > smallBuffer)
		{
			if (inFile.size() > bigBufferThreshold)
			{
				readSize = bigBuffer;
			}
			else
			{
				readSize = smallBuffer;
			}
		}
		else
		{
			readSize = inFile.size();
		}
		buffer.reserve(readSize);

		qint64 sizeReadTmp(inFile.read(&buffer[0], readSize));
		switch (hashType_pri)
		{
		case hashType_ec::crc32c:
		{
			do
			{
				hash32BitNumberResult_pri = crc32c_append(
				            hash32BitNumberResult_pri
				            , reinterpret_cast<const uint8_t*>(&buffer[0])
				        , sizeReadTmp
				);
				sizeReadTmp = inFile.read(&buffer[0], readSize);
			} while ((sizeReadTmp > 0) and (inFile.bytesAvailable() >= readSize));
			if (sizeReadTmp < 0)
			{
				//error
				appendError_f("Error while reading file: " + inputFilePath_pri);
#ifdef DEBUGJOUVEN
				//QOUT_TS("(downloadServerSocket_c::readyRead_f) error sizeread " << sizeReadTmp << endl);
#endif
            }
            else
            {
                if (sizeReadTmp > 0)
                {
                    hash32BitNumberResult_pri = crc32c_append(
                                hash32BitNumberResult_pri
                                , reinterpret_cast<const uint8_t*>(&buffer[0])
                            , sizeReadTmp
                    );
                }
            }
            hash32BitNumberResultSet_pri = true;
        }
            break;
        case hashType_ec::XXHASH64:
        {
#define XXHSUM64_DEFAULT_SEED 0
            if (inFile.size() > readSize)
            {
                XXH64_state_t state64;
                XXH64_reset(&state64, XXHSUM64_DEFAULT_SEED);
                do
                {
                    XXH64_update(&state64, &buffer[0], sizeReadTmp);
                    sizeReadTmp = inFile.read(&buffer[0], readSize);
                } while ((sizeReadTmp > 0) and (inFile.bytesAvailable() >= readSize));
                if (sizeReadTmp < 0)
                {
                    //error
                    appendError_f("Error while reading file: " + inputFilePath_pri);
#ifdef DEBUGJOUVEN
                    //QOUT_TS("(downloadServerSocket_c::readyRead_f) error sizeread " << sizeReadTmp << endl);
#endif
                }
                else
                {
                    if (sizeReadTmp > 0)
                    {
                        XXH64_update(&state64, &buffer[0], sizeReadTmp);
                    }
                }
                hash64BitNumberResult_pri = XXH64_digest(&state64);
            }
            else
            {
                hash64BitNumberResult_pri = XXH64(&buffer[0], sizeReadTmp, XXHSUM64_DEFAULT_SEED);
            }
            hash64BitNumberResultSet_pri = true;
        }
            break;
        case hashType_ec::whirlpool:
        {
            CryptoPP::Whirlpool hash;
            do
            {
                hash.Update(reinterpret_cast<const byte*>(&buffer[0]), sizeReadTmp);
                sizeReadTmp = inFile.read(&buffer[0], readSize);
            } while ((sizeReadTmp > 0) and (inFile.bytesAvailable() >= readSize));
            if (sizeReadTmp < 0)
            {
                //error
                appendError_f("Error while reading file: " + inputFilePath_pri);
#ifdef DEBUGJOUVEN
                //QOUT_TS("(downloadServerSocket_c::readyRead_f) error sizeread " << sizeReadTmp << endl);
#endif
            }
            else
            {
                if (sizeReadTmp > 0)
                {
                    hash.Update(reinterpret_cast<const byte*>(&buffer[0]), sizeReadTmp);
                }
            }
            digest_pri.resize(CryptoPP::Whirlpool::DIGESTSIZE);
            hash.Final(&digest_pri[0]);
        }
            break;
        case hashType_ec::SHA256:
        {
            CryptoPP::SHA256 hash;
            do
            {
                hash.Update(reinterpret_cast<const byte*>(&buffer[0]), sizeReadTmp);
                sizeReadTmp = inFile.read(&buffer[0], readSize);
            } while ((sizeReadTmp > 0) and (inFile.bytesAvailable() >= readSize));
            if (sizeReadTmp < 0)
            {
                //error
                appendError_f("Error while reading file: " + inputFilePath_pri);
#ifdef DEBUGJOUVEN
                //QOUT_TS("(downloadServerSocket_c::readyRead_f) error sizeread " << sizeReadTmp << endl);
#endif
            }
            else
            {
                if (sizeReadTmp > 0)
                {
                    hash.Update(reinterpret_cast<const byte*>(&buffer[0]), sizeReadTmp);
                }
            }
            digest_pri.resize(CryptoPP::SHA256::DIGESTSIZE);
            hash.Final(&digest_pri[0]);
        }
            break;
        };
    }
    else
    {
        appendError_f("Couldn't open file: " + inputFilePath_pri);
    }
    //#ifdef DEBUGJOUVEN
    //			DEBUGSOURCEEND
    //#endif
}

void hasher_c::hashString_f()
{
	//#ifdef DEBUGJOUVEN
	//			DEBUGSOURCEBEGIN
	//#endif

	//char buffer[BUFFERSIZE];
	switch (hashType_pri)
	{
	case hashType_ec::crc32c:
	{
		hash32BitNumberResult_pri = crc32c_append(
		            hash32BitNumberResult_pri
		            , reinterpret_cast<const uint8_t*>(inputString_pri.data())
		        , inputString_pri.size()
		);
		hash32BitNumberResultSet_pri = true;
	}
		break;
	case hashType_ec::XXHASH64:
	{
#define XXHSUM64_DEFAULT_SEED 0
        hash64BitNumberResult_pri = XXH64(inputString_pri.data(), inputString_pri.size(), XXHSUM64_DEFAULT_SEED);
        hash64BitNumberResultSet_pri = true;
    }
        break;
    case hashType_ec::whirlpool:
    {
        CryptoPP::Whirlpool hash;
        hash.Update(reinterpret_cast<const byte*>(inputString_pri.data()), inputString_pri.size());
        digest_pri.resize(CryptoPP::Whirlpool::DIGESTSIZE);
        hash.Final(&digest_pri[0]);
    }
        break;
    case hashType_ec::SHA256:
    {
        CryptoPP::SHA256 hash;
        hash.Update(reinterpret_cast<const byte*>(inputString_pri.data()), inputString_pri.size());
        digest_pri.resize(CryptoPP::SHA256::DIGESTSIZE);
        hash.Final(&digest_pri[0]);
    }
        break;
    };
    //#ifdef DEBUGJOUVEN
    //			DEBUGSOURCEEND
    //#endif
}

void hasher_c::doEncode_f()
{
	//#ifdef DEBUGJOUVEN
	//			DEBUGSOURCEBEGIN
	//#endif

	//otherwise the bigger hashes won't have output at all
	if (outputType_pri == outputType_ec::unsignedXbitInteger and not (hashType_pri == hashType_ec::crc32c or hashType_pri == hashType_ec::XXHASH64))
	{
		//nothing
		outputType_pri = outputType_ec::decimalString;
	}
	else
	{

	}

	switch (outputType_pri)
	{
	case outputType_ec::unsignedXbitInteger:
	{
		//do nothing, it's done one the hash phase for those able to fit in a number
	}
		break;
	case outputType_ec::base64String:
	{
		if (hash64BitNumberResultSet_pri and digest_pri.empty())
		{
			digest_pri = intToByte_f(hash64BitNumberResult_pri);
		}

		if (hash32BitNumberResultSet_pri and digest_pri.empty())
		{
			digest_pri = intToByte_f(hash32BitNumberResult_pri);
		}

		CryptoPP::Base64Encoder encoder(new CryptoPP::StringSink(hashStringResult_pri), false);
		encoder.Put(&digest_pri[0], digest_pri.size());
		encoder.MessageEnd();
		hashStringResultSet_pri = true;
	}
		break;
	case outputType_ec::hexadecimalString:
	{
		if (hash64BitNumberResultSet_pri and digest_pri.empty())
		{
			digest_pri = intToByte_f(hash64BitNumberResult_pri);
		}

		if (hash32BitNumberResultSet_pri and digest_pri.empty())
		{
			digest_pri = intToByte_f(hash32BitNumberResult_pri);
		}

		CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(hashStringResult_pri), true);
		encoder.Put(&digest_pri[0], digest_pri.size());
		encoder.MessageEnd();
		hashStringResultSet_pri = true;
	}
		break;
	case outputType_ec::decimalString:
	{
		if (hash64BitNumberResultSet_pri and digest_pri.empty())
		{
			digest_pri = intToByte_f(hash64BitNumberResult_pri);
		}

		if (hash32BitNumberResultSet_pri and digest_pri.empty())
		{
			digest_pri = intToByte_f(hash32BitNumberResult_pri);
		}

		CryptoPP::Integer integerTmp(&digest_pri[0], digest_pri.size());
		hashStringResult_pri = CryptoPP::IntToString<CryptoPP::Integer>(integerTmp, 10);
		hashStringResultSet_pri = true;
	}
		break;
	};
	//#ifdef DEBUGJOUVEN
	//			DEBUGSOURCEEND;
	//#endif
}

hasher_c::hasher_c(const inputType_ec inputType_par_con
                   , const QString &input_par_con
                   , const outputType_ec outputType_par_con
                   , const hashType_ec hashType_par_con) :
    inputType_pri(inputType_par_con)
  , outputType_pri(outputType_par_con)
  , hashType_pri(hashType_par_con)
{
    if (inputType_par_con == inputType_ec::file)
    {
        inputFilePath_pri = input_par_con;
    }
    if (inputType_par_con == inputType_ec::string)
    {
        inputString_pri.append(input_par_con);
    }
}

}
