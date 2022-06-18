#include <bits/stdc++.h>

#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#endif

using namespace std;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "cryptopp/integer.h"
using CryptoPP::Integer;

#include "cryptopp/sha.h"
using CryptoPP::SHA256;

#include "cryptopp/filters.h"
using CryptoPP::ArraySink;
using CryptoPP::SignatureVerificationFilter;
using CryptoPP::SignerFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;

#include "cryptopp/files.h"
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include "cryptopp/eccrypto.h"
using CryptoPP::DL_GroupParameters_EC;
using CryptoPP::ECDSA;
using CryptoPP::ECP;

#include "cryptopp/oids.h"
using CryptoPP::OID;

#include "cryptopp/hex.h"
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;

#define nValue 10000

// convert wstring to string
wstring s2ws(const std::string &str)
{
	using convert_type = std::codecvt_utf8<wchar_t>;
	std::wstring_convert<convert_type, wchar_t> converter;
	return converter.from_bytes(str);
}

// Convert wstring to string
string ws2s(const std::wstring &wstr)
{
	using convert_type = std::codecvt_utf8<wchar_t>;
	std::wstring_convert<convert_type, wchar_t> converter;
	return converter.to_bytes(wstr);
}

// convert integer to wstring
wstring in2ws(const CryptoPP::Integer &t)
{
	std::ostringstream oss;
	oss.str("");
	oss.clear();
	oss << t;
	std::string encoded(oss.str());
	std::wstring_convert<codecvt_utf8<wchar_t>> towstring;
	return towstring.from_bytes(encoded);
}

// convert byte string to hex wstring cryptopp::byte
void BeautifulPrinter(string byteString)
{
	string encodedCode = "";
	StringSource(byteString, true,
				 new HexEncoder(
					 new StringSink(encodedCode)));
	wstring wstr = s2ws(encodedCode);
	wcout << wstr << endl;
}

// convert byte string to hex wstring cryptopp::byte
wstring BeautifulPrinterForFile(string byteString)
{
	string encodedCode = "";
	StringSource(byteString, true,
				 new HexEncoder(
					 new StringSink(encodedCode)));
	wstring wstr = s2ws(encodedCode);
	return wstr;
}

//get the plaintext from the file
string getPlaintextFromFile(string filename)
{
	string plaintext;
	ifstream file(filename);
	if (file.is_open())
	{
		getline(file, plaintext);
		file.close();
	}
	else
	{
		wcout << L"Unable to open file!" << endl;
		exit(1);
	}
	return plaintext;
}

//get the signature from the file
void getSignatureFromFile(string filename, string &signature)
{
    ifstream ifs(filename);
    if (ifs.is_open())
    {
        string line;
        while (ifs.good())
        {
            getline(ifs, line);
            signature += line;
        }
        ifs.close();
    }
    else
    {
        wcout << "Cannot open file " << s2ws(filename) << "!" << endl;
        exit(1);
    }
}

//function to get the working directory
int selectWork()
{
	int choice;
	wcout << L"1. Generate keys and write to files" << endl;
	wcout << L"2. Sign a file" << endl;
	wcout << L"3. Verify a file" << endl;
	wcout << L"Enter your choice: ";
	try
	{
		wcin >> choice;
		if (choice < 1 || choice > 3)
		{
			wcout << L"Invalid choice!" << endl;
			exit(1);
		}
	}
	catch (const std::exception &e)
	{
		wcout << e.what() << '\n';
		exit(1);
	}
	return choice;
}

//function to generate private key
bool generatePrivateKey(const OID &oid, ECDSA<ECP, SHA256>::PrivateKey &key)
{
	AutoSeededRandomPool prng;
	key.Initialize(prng, oid);
	return key.Validate(prng, 3);
}

//function to generate public key
bool generatePublicKey(const ECDSA<ECP, SHA256>::PrivateKey &privateKey, ECDSA<ECP, SHA256>::PublicKey &publicKey)
{
	AutoSeededRandomPool prng;
	privateKey.MakePublicKey(publicKey);
	return publicKey.Validate(prng, 3);
}

//function to print the domain parameters withe parameters
void printDomainParameters(const DL_GroupParameters_EC<ECP> &parameters)
{
	wcout << endl;
	wcout << "Modulus:" << endl;
	wcout << in2ws(parameters.GetCurve().GetField().GetModulus()) << endl;
	wcout << "Coefficient:" << endl;
	wcout << "A: " << in2ws(parameters.GetCurve().GetA()) << endl;
	wcout << "B: " << in2ws(parameters.GetCurve().GetB()) << endl;
	wcout << "BasePoint:" << endl;
	wcout << "X: " << in2ws(parameters.GetSubgroupGenerator().x) << endl;
	wcout << "Y: " << in2ws(parameters.GetSubgroupGenerator().y) << endl;
	wcout << "SubgroupOrder:" << endl;
	wcout << in2ws(parameters.GetSubgroupOrder()) << endl;
	wcout << "Cofactor:" << endl;
	wcout << in2ws(parameters.GetCofactor()) << endl;
}

//function to print the domain parameters with private key
void printDomainParameters(const ECDSA<ECP, SHA256>::PrivateKey &key)
{
	printDomainParameters(key.GetGroupParameters());
}

//function to print the domain parameters with public key
void printDomainParameters(const ECDSA<ECP, SHA256>::PublicKey &key)
{
	printDomainParameters(key.GetGroupParameters());
}

//function to print the private key
void printPrivateKey(const ECDSA<ECP, SHA256>::PrivateKey &key)
{
	wcout << "PrivateExponent:" << endl;
	wcout << in2ws(key.GetPrivateExponent()) << endl;
}

//function to print the public key
void printPublicKey(const ECDSA<ECP, SHA256>::PublicKey &key)
{
	wcout << "PublicElement:" << endl;
	wcout << "X: " << in2ws(key.GetPublicElement().x) << endl;
	wcout << "Y: " << in2ws(key.GetPublicElement().y) << endl;
}

//function to print the key
void printKey(const ECDSA<ECP, SHA256>::PrivateKey &privateKey, const ECDSA<ECP, SHA256>::PublicKey &publicKey)
{
	printDomainParameters(privateKey);
	printPrivateKey(privateKey);
	printPublicKey(publicKey);
}

//function to generate key and validate it
bool generateKey(const OID &oid, string filePrivateKey, string filePublicKey)
{
	ECDSA<ECP, SHA256>::PrivateKey privateKey;
	ECDSA<ECP, SHA256>::PublicKey publicKey;

	if (generatePrivateKey(oid, privateKey) == false || generatePublicKey(privateKey, publicKey) == false)
	{
		return false;
	}

	privateKey.Save(FileSink(filePrivateKey.c_str(), true).Ref());
	publicKey.Save(FileSink(filePublicKey.c_str(), true).Ref());
	printKey(privateKey, publicKey);

	return true;
}

//function to sign the message
string signMessage(const string &message, const ECDSA<ECP, SHA256>::PrivateKey &privateKey)
{
	AutoSeededRandomPool prng;
	string signature;
	signature.clear();

	StringSource(message, true,
				 new SignerFilter(prng,
								  ECDSA<ECP, SHA256>::Signer(privateKey),
								  new StringSink(signature)));
	return signature;
}

//load the private key from file
void loadPrivateKey(const string &filename, ECDSA<ECP, SHA256>::PrivateKey &key)
{
	key.Load(FileSource(filename.c_str(), true).Ref());
}

//load the public key from file
void loadPublicKey(const string &filename, ECDSA<ECP, SHA256>::PublicKey &key)
{
	key.Load(FileSource(filename.c_str(), true).Ref());
}

//function to set up the signature
void setUpSignature(string filePrivateKey, string fileMessage, string &signature)
{
	ECDSA<ECP, SHA256>::PrivateKey privateKey;

	loadPrivateKey(filePrivateKey, privateKey);

	string message = getPlaintextFromFile(fileMessage);
	double timeCounter = 0.0;

	for (int i = 0; i < nValue; ++i)
	{
		double startTime = clock();
		signature = signMessage(message, privateKey);
		if (signature.empty())
		{
			wcout << L"Signature is empty!" << endl;
			exit(1);
		}
		double endTime = clock();
		timeCounter += (endTime - startTime);
	}
	//printDomainParameters(privateKey);
	//printPrivateKey(privateKey);
	wcout << L"Signature: ";
	BeautifulPrinter(signature);
	wcout << L"Average time: " << timeCounter / nValue << " ms" << endl;
}

// function to sign the file
void putSignatureToFile(string filename, const string &signature)
{
	ofstream file(filename);
	try
	{
		file << signature;
		file.close();
	}
	catch (const std::exception &e)
	{
		wcout << e.what() << '\n';
		exit(1);
	}
}

//function to verify the signature
bool verifyMessage(const ECDSA<ECP, SHA256>::PublicKey &publicKey, const string &message, const string &signature)
{
	bool result = false;
	StringSource(signature + message, true,
				 new SignatureVerificationFilter(
					 ECDSA<ECP, SHA256>::Verifier(publicKey),
					 new ArraySink((CryptoPP::byte *)&result, sizeof(result))));
	return result;
}


//function to set up the verification
void setUpVerification(string filePublicKey, string fileMessage, string fileSignature)
{
	ECDSA<ECP, SHA256>::PublicKey publicKey;

	loadPublicKey(filePublicKey, publicKey);

	string message = getPlaintextFromFile(fileMessage);
	
	string signature;
	getSignatureFromFile(fileSignature, signature);

	double timeCounter = 0.0;

	for (int i = 0; i < nValue; ++i)
	{
		double startTime = clock();
		if(verifyMessage(publicKey, message, signature) == false)
		{
			wcout << L"Verification failed!" << endl;
			exit(1);
		}
		double endTime = clock();
		timeCounter += (endTime - startTime);
	}
	
	//printDomainParameters(publicKey);
	//printPublicKey(publicKey);
	wcout << L"Signature: ";
	BeautifulPrinter(signature);
	wcout << L"Average time: " << timeCounter / nValue << " ms" << endl;
}

//set up vietnamese language
void setUpVietnamese()
{
#ifdef _WIN32
	_setmode(_fileno(stdin), _O_U16TEXT);
	_setmode(_fileno(stdout), _O_U16TEXT);
#elif __linux__
	setlocale(LC_ALL, "");
#endif
}

int main(int argc, char **argv)
{
	setUpVietnamese();

	int choice = selectWork();
	string signature;
	string slash;

#ifdef _WIN32
	slash = '\\';
#elif __linux__
	slash = '/';
#endif

	string filePublicKey = "." + slash + "eccPublic.key";
	string filePrivateKey = "." + slash + "eccPrivate.key";
	string fileMessage = "." + slash + "message.txt";
	string fileSignature = "." + slash + "signature.txt";

	switch (choice)
	{
	case 1:
		try
		{
			if (generateKey(CryptoPP::ASN1::secp256r1(), filePrivateKey, filePublicKey) == true)
			{
				wcout << L"Keys generated successfully!" << endl;
			}
			else
			{
				wcout << L"Keys generation failed!" << endl;
			}
		}
		catch (const std::exception &e)
		{
			wcout << L"Error when generating keys!" << endl;
			wcout << e.what() << endl;
			exit(1);
		}
		break;

	case 2:
		try
		{
			setUpSignature(filePrivateKey, fileMessage, signature);
			putSignatureToFile(fileSignature, signature);
			wcout << L"Signature saved successfully!" << endl;
		}
		catch (const CryptoPP::Exception &e)
		{
			wcout << L"Error when signing message!" << endl;
			wcout << e.what() << endl;
			exit(1);
		}
		break;

	case 3:
		try
		{
			setUpVerification(filePublicKey, fileMessage, fileSignature);
			wcout << L"Message verified successfully!" << endl;
		}
		catch (const CryptoPP::Exception &e)
		{
			wcout << L"Error when verifying signature!" << endl;
			wcout << e.what() << endl;
			exit(1);
		}
		break;
		
	default:
		wcout << "Invalid choice!" << endl;
		break;
	}
	return 0;
}