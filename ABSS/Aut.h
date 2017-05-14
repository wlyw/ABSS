#ifndef AUT_H_
#define AUT_H_

#include "randpool.h"
#include "rsa.h"
#include "hex.h"
#include "files.h"
#include "modes.h"
#include "default.h"
#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "eccrypto.h"
using CryptoPP::ECP;
using CryptoPP::ECDSA;

#include "sha.h"
using CryptoPP::SHA1;

#include "queue.h"
using CryptoPP::ByteQueue;

#include "oids.h"
using CryptoPP::OID;

#include "asn.h"
using namespace CryptoPP::ASN1;

#include "integer.h"
using CryptoPP::Integer;
//#include "validate.h"
#include<string>
using std::string;
using std::cout;
using std::cerr;
using std::endl;
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

void LoadPrivateKey(const string& filename, ECDSA<ECP, SHA1>::PrivateKey& key)
{
	key.Load(FileSource(filename.c_str(), true /*pump all*/).Ref());
}

void LoadPublicKey(const string& filename, ECDSA<ECP, SHA1>::PublicKey& key)
{
	key.Load(FileSource(filename.c_str(), true /*pump all*/).Ref());
}

void ECCkeyger(const string& prifile, const string& pubfile) {
	AutoSeededRandomPool prng;

	ECDSA<ECP, SHA1>::PrivateKey privKey;
	privKey.Initialize(prng, secp224r1());
	privKey.Save(FileSink(prifile.c_str(), true /*binary*/).Ref());

	ECDSA<ECP, SHA1>::PublicKey pubKey;
	privKey.MakePublicKey(pubKey);
	pubKey.Save(FileSink(pubfile.c_str(), true /*binary*/).Ref());
}

void ECCSign(const ECDSA<ECP, SHA1>::PrivateKey& key, const string& message, string& signature) {
	AutoSeededRandomPool prng;

	signature.erase();

	StringSource(message, true,
		new SignerFilter(prng,
			ECDSA<ECP, SHA1>::Signer(key),
			new StringSink(signature)
		) // SignerFilter
	); // StringSource
}

bool ECCCheck(const ECDSA<ECP, SHA1>::PublicKey& key, const string& message, const string& signature) {
	bool result = false;

	StringSource(signature + message, true,
		new SignatureVerificationFilter(
			ECDSA<ECP, SHA1>::Verifier(key),
			new ArraySink((byte*)&result, sizeof(result))
		) // SignatureVerificationFilter
	);

	return result;
}

#endif // !AUT_H_
