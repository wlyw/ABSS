#include<iostream>
#include "SS.h"
#include "Aut.h"
using namespace std;

#pragma comment(lib, "cryptopp\\lib\\cryptlib.lib")

int main() {
	//char* filename = "D:\\Documentation\\in.txt";
	char* seed = "201759";
	//SecretShareFile(3, 5, filename, seed);

	/*
	char* outfilename = "D:\\Documentation\\out.txt";
	char* infilenames[] = { "D:\\Documentation\\in.txt.000",
		"D:\\Documentation\\in.txt.003",
		"D:\\Documentation\\in.txt.004" };
	SecretRecoverFile(3, outfilename, infilenames);
	*/
	
	//RSADecryptString(const char *privFilename, const char *ciphertext)//Ω‚√‹
	char* privfilename = "D:\\Documentation\\priv.txt";
	char* pubfilename = "D:\\Documentation\\pub.txt";
	GenerateRSAKey(2048, privfilename, pubfilename, seed);

	string Enc = RSAEncryptString(pubfilename, seed, "helloworld");
	cout << Enc << endl;

	string Dec = RSADecryptString(privfilename, Enc.c_str());
	cout << Dec << endl;

	return 0;
}