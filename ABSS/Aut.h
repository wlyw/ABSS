#ifndef AUT_H_
#define AUT_H_

#include "randpool.h"
#include "rsa.h"
#include "hex.h"
#include "files.h"
#include "modes.h"
#include "default.h"
//#include "validate.h"
#include<string>
using std::string;
using namespace CryptoPP;

namespace { OFB_Mode<AES>::Encryption s_globalRNG; }
RandomNumberGenerator & GlobalRNG()
{
	return dynamic_cast<RandomNumberGenerator&>(s_globalRNG);
}

//产生公钥密钥文件
void GenerateRSAKey(unsigned int keyLength, const char *privFilename, const char *pubFilename, const char *seed)
{
	RandomPool randPool;
	randPool.Put((byte *)seed, strlen(seed));

	RSAES_OAEP_SHA_Decryptor  priv(randPool, keyLength);
	HexEncoder privFile(new FileSink(privFilename));
	priv.DEREncode(privFile);  
	privFile.MessageEnd();

	RSAES_OAEP_SHA_Encryptor pub(priv);
	HexEncoder pubFile(new FileSink(pubFilename));
	pub.DEREncode(pubFile);
	pubFile.MessageEnd();
}

string RSAEncryptString(const char *pubFilename, const char *seed, const char *message)//加密
{
	FileSource pubFile(pubFilename, true, new HexDecoder);
	RSAES_OAEP_SHA_Encryptor pub(pubFile);

	RandomPool randPool;
	randPool.IncorporateEntropy((byte *)seed, strlen(seed));

	string result;
	StringSource(message, true, new PK_EncryptorFilter(randPool, pub, new HexEncoder(new StringSink(result))));
	return result;
}

string RSADecryptString(const char *privFilename, const char *ciphertext)//解密
{
	std::string seed = IntToString(time(NULL));
	seed.resize(16, ' ');
	OFB_Mode<AES>::Encryption& prng = dynamic_cast<OFB_Mode<AES>::Encryption&>(GlobalRNG());
	prng.SetKeyWithIV((byte *)seed.data(), 16, (byte *)seed.data());

	FileSource privFile(privFilename, true, new HexDecoder);
	RSAES_OAEP_SHA_Decryptor priv(privFile);

	string result;
	StringSource(ciphertext, true, new HexDecoder(new PK_DecryptorFilter(GlobalRNG(), priv, new StringSink(result))));
	return result;
}

#endif // !AUT_H_
