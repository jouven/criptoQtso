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
#include "backwardSTso/backward.hpp"
#endif

#include <QFile>

#include <cstdint>
#include <vector>

struct XXH64_state_s
{
   uint_fast64_t total_len;
   uint_fast64_t v1;
   uint_fast64_t v2;
   uint_fast64_t v3;
   uint_fast64_t v4;
   uint_fast64_t mem64[4];   /* buffer defined as U64 for alignment */
   uint_fast64_t memsize;
};
typedef XXH64_state_s XXH64_state_t;

namespace eines
{

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
		if (input_pri.isEmpty())
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
		if (input_pri.isEmpty())
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

uint_fast64_t hasher_c::hashNumberResult_f() const
{
	return hashNumberResult_pri;
}

bool hasher_c::hashNumberResultSet_f() const
{
	return hashNumberResultSet_pri;
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

	QFile inFile(input_pri);
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
				hashNumberResult_pri = crc32c_append(
				            hashNumberResult_pri
				            , reinterpret_cast<const uint8_t*>(&buffer[0])
				        , sizeReadTmp
				);
				sizeReadTmp = inFile.read(&buffer[0], readSize);
			} while ((sizeReadTmp > 0) and (inFile.bytesAvailable() >= readSize));
			if (sizeReadTmp < 0)
			{
				//error
				appendError_f("Error while reading file: " + input_pri);
#ifdef DEBUGJOUVEN
				//QOUT_TS("(downloadServerSocket_c::readyRead_f) error sizeread " << sizeReadTmp << endl);
#endif
            }
            else
            {
                if (sizeReadTmp > 0)
                {
                    hashNumberResult_pri = crc32c_append(
                                hashNumberResult_pri
                                , reinterpret_cast<const uint8_t*>(&buffer[0])
                            , sizeReadTmp
                    );
                }
            }
            hashNumberResultSet_pri = true;
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
                    appendError_f("Error while reading file: " + input_pri);
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
                hashNumberResult_pri = XXH64_digest(&state64);
            }
            else
            {
                hashNumberResult_pri = XXH64(&buffer[0], sizeReadTmp, XXHSUM64_DEFAULT_SEED);
            }
            hashNumberResultSet_pri = true;
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
                appendError_f("Error while reading file: " + input_pri);
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
                appendError_f("Error while reading file: " + input_pri);
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
        appendError_f("Couldn't open file: " + input_pri);
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
		hashNumberResult_pri = crc32c_append(
		            hashNumberResult_pri
		            , reinterpret_cast<const uint8_t*>(input_pri.data())
		        , input_pri.size()
		);
		hashNumberResultSet_pri = true;
	}
		break;
	case hashType_ec::XXHASH64:
	{
#define XXHSUM64_DEFAULT_SEED 0
        hashNumberResult_pri = XXH64(input_pri.data(), input_pri.size(), XXHSUM64_DEFAULT_SEED);
        hashNumberResultSet_pri = true;
    }
        break;
    case hashType_ec::whirlpool:
    {
        CryptoPP::Whirlpool hash;
        hash.Update(reinterpret_cast<const byte*>(input_pri.data()), input_pri.size());
        digest_pri.resize(CryptoPP::Whirlpool::DIGESTSIZE);
        hash.Final(&digest_pri[0]);
    }
        break;
    case hashType_ec::SHA256:
    {
        CryptoPP::SHA256 hash;
        hash.Update(reinterpret_cast<const byte*>(input_pri.data()), input_pri.size());
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
	switch (outputType_pri)
	{
	case outputType_ec::number:
	{
		//do nothing, it's done one the hash phase for those able to fit in a number
	}
		break;
	case outputType_ec::base64:
	{
		if (hashNumberResultSet_pri)
		{
			hashStringResult_pri = CryptoPP::IntToString<uint_fast64_t>(hashNumberResult_pri, 64);
		}

		if (hashStringResult_pri.empty() and not digest_pri.empty())
		{
			CryptoPP::Base64Encoder encoder;
			encoder.Attach(new CryptoPP::StringSink(hashStringResult_pri));
			encoder.Put(&digest_pri[0], digest_pri.size());
			encoder.MessageEnd();
		}
		hashStringResultSet_pri = true;
	}
		break;
	case outputType_ec::hex:
	{
		if (hashNumberResultSet_pri)
		{
			hashStringResult_pri = CryptoPP::IntToString<uint_fast64_t>(hashNumberResult_pri, 16);
		}

		if (hashStringResult_pri.empty() and not digest_pri.empty())
		{
			CryptoPP::HexEncoder encoder;
			encoder.Attach(new CryptoPP::StringSink(hashStringResult_pri));
			encoder.Put(&digest_pri[0], digest_pri.size());
			encoder.MessageEnd();
		}
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
  , input_pri(input_par_con)
  , outputType_pri(outputType_par_con)
  , hashType_pri(hashType_par_con)
{
}

}
