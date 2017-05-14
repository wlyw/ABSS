#include<iostream>
#include<Windows.h>
#include<bitset>
#include "SS.h"
#include "Aut.h"
using namespace std;

#pragma comment(lib, "cryptopp\\lib\\cryptlib.lib")

string stringTobinary(string str) {
	string res;
	for (auto each : str) {
		string tmp;
		for (int i = 0; i < 8; ++i) {
			if (each & 1) tmp.push_back('1');
			else tmp.push_back('0');
			each >>= 1;
		}
		reverse(tmp.begin(), tmp.end());
		res += tmp;
	}
	return res;
}

int main() {
	//char* filename = "D:\\Documentation\\in.txt";
	char* seed = "2017514";
	//SecretShareFile(3, 5, filename, seed);

	/*
	char* outfilename = "D:\\Documentation\\out.txt";
	char* infilenames[] = { "D:\\Documentation\\in.txt.000",
		"D:\\Documentation\\in.txt.003",
		"D:\\Documentation\\in.txt.004" };
	SecretRecoverFile(3, outfilename, infilenames);
	*/
	
	//RSADecryptString(const char *privFilename, const char *ciphertext)//解密
	/*char* privfilename = "D:\\Documentation\\priv.txt";
	char* pubfilename = "D:\\Documentation\\pub.txt";
	GenerateRSAKey(2048, privfilename, pubfilename, seed);

	string Enc = RSAEncryptString(pubfilename, seed, "helloworld");
	cout << Enc << endl;

	string Dec = RSADecryptString(privfilename, Enc.c_str());
	cout << Dec << endl;*/

	char* prifile = "ec.pri.key";
	char* pubfile = "ec.pub.key";
	ECCkeyger(prifile, pubfile);

	DWORD start_time = GetTickCount();
	SecretShareFile(3, 5, pubfile, seed);
	char* outfilename = "ec.test.key";
	char* infilenames[] = { "ec.pub.key.000",
		"ec.pub.key.001",
		"ec.pub.key.002"};
	SecretRecoverFile(3, outfilename, infilenames);
	
	ECDSA<ECP, SHA1>::PrivateKey privateKey;
	ECDSA<ECP, SHA1>::PublicKey publicKey;
	LoadPrivateKey( "ec.pri.key", privateKey );
	LoadPublicKey( "ec.test.key", publicKey );

	string message = "hello world!";
	string signature;

	DWORD mid_time = GetTickCount();
	ECCSign(privateKey, message, signature);
	cout << "消息:" << endl;
	cout << message << endl;
	cout << "签名(二进制):" << endl;
	cout << stringTobinary(signature) << endl;

	if (ECCCheck(publicKey, message, signature))
		cout << "pass";
	else cout << "error";
	DWORD end_time = GetTickCount();
	cout << endl << mid_time - start_time << endl;
	cout << endl << end_time - start_time << endl;

	getchar();
	return 0;
}