#include <bits/stdc++.h>

using namespace std;

#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#endif

#include "cryptopp/rsa.h"
using CryptoPP::InvertibleRSAFunction;
using CryptoPP::RSA;
using CryptoPP::RSAES_OAEP_SHA_Decryptor;
using CryptoPP::RSAES_OAEP_SHA_Encryptor;

#include "cryptopp/filters.h"
using CryptoPP::PK_DecryptorFilter;
using CryptoPP::PK_EncryptorFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;

#include "cryptopp/files.h"
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "cryptopp/queue.h"
using CryptoPP::ByteQueue;

#include "cryptopp/cryptlib.h"
using CryptoPP::BufferedTransformation;
using CryptoPP::Exception;
using CryptoPP::PrivateKey;
using CryptoPP::PublicKey;

#include "cryptopp/hex.h"
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;

#include "cryptopp/nbtheory.h"
#include "cryptopp/modarith.h"
#include "cryptopp/integer.h"
using CryptoPP::Integer;

#define nValue 10000

// set up the Vietnamese language
void setUpVietnamese()
{
#ifdef _WIN32
	_setmode(_fileno(stdin), _O_U16TEXT);
	_setmode(_fileno(stdout), _O_U16TEXT);
#elif __linux__
	setlocale(LC_ALL, "");
#endif
}

// Convert string to wstring
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

//convert byte string to hex wstring cryptopp::byte
string BeautifulPrinterForFileString(string str)
{
	string encodedCode = "";
	StringSource(str, true,
				 new HexEncoder(
					 new StringSink(encodedCode)));
	return encodedCode;
}

//get the key from file
void getKeyFromFile(const string &filename, BufferedTransformation &bufferedTransformation)
{
    FileSource file(filename.c_str(), true);
    file.TransferTo(bufferedTransformation);
    bufferedTransformation.MessageEnd();
}

//get private key from file
void getPrivateKeyFromFile(const string &filename, PrivateKey &key)
{
	ByteQueue queueOfByte;
    getKeyFromFile(filename, queueOfByte);
    key.Load(queueOfByte);
}

//get public key from file
void getPublicKeyFromFile(const string &filename, PublicKey &key)
{
	ByteQueue queueOfByte;
	getKeyFromFile(filename, queueOfByte);
	key.Load(queueOfByte);
}

//decode the hex string from the input file
string decodeCiphertext(const wstring &wciphertext)
{
    string ciphertext;
    StringSource(ws2s(wciphertext), true,
                 new HexDecoder(new StringSink(ciphertext)));
    return ciphertext;
}

// select encrypt or decrypt
int selectEncDec()
{
	int choice;
	wcout << L"Encrypt or Decrypt?" << endl;
	wcout << L"1. Encrypt" << endl;
	wcout << L"2. Decrypt" << endl;
	wcout << L"Enter your choice: ";
	try
	{
		wcin >> choice;
		if (choice < 1 || choice > 2)
		{
			wcout << L"Invalid choice!" << endl;
			exit(1);
		}
	}
	catch (const exception &exc)
	{
		wcout << exc.what() << '\n';
		exit(1);
	}

	return choice;
}

//get the type of input
int selectTypeOfInput()
{
	int choice;
	wcout << L"Input from file or keyboard?" << endl;
	wcout << L"1. File" << endl;
	wcout << L"2. Keyboard" << endl;
	try
	{
		wcin >> choice;
		if (choice < 1 || choice > 2)
		{
			wcout << L"Invalid choice!" << endl;
			exit(1);
		}
	}
	catch (const exception &exc)
	{
		wcout << exc.what() << '\n';
		exit(1);
	}

	return choice;
}

//this is the rsa encryption function
string rsaEncrypt(AutoSeededRandomPool &prng, const RSA::PublicKey &rsaPublicKey, const string &plaintext)
{
	string ciphertext;
	RSAES_OAEP_SHA_Encryptor encryptor(rsaPublicKey);
	StringSource(plaintext, true,
				 new PK_EncryptorFilter(prng, encryptor,
										new StringSink(ciphertext)));
	return ciphertext;
}

//this is the rsa decryption function
string rsaDecrypt(AutoSeededRandomPool &prng, const RSA::PrivateKey &rsaPrivateKey, const string &ciphertext)
{
	string recovertext;
	RSAES_OAEP_SHA_Decryptor decryptor(rsaPrivateKey);
	StringSource(ciphertext, true,
				 new PK_DecryptorFilter(prng, decryptor,
										new StringSink(recovertext)));
	return recovertext;
}

//this is the rsa function to get the key and validate the key
void getKeyFromFileAndValidate(RSA::PrivateKey &rsaPrivateKey, RSA::PublicKey &rsaPublicKey)
{
	AutoSeededRandomPool prng;
    try
    {        

#ifdef _WIN32
		getPrivateKeyFromFile(".\\rsaPrivate.key", rsaPrivateKey);
        getPublicKeyFromFile(".\\rsaPublic.key", rsaPublicKey);
        
#elif __linux__
        getPrivateKeyFromFile("./rsaPrivate.key", rsaPrivateKey);
        getPublicKeyFromFile("./rsaPublic.key", rsaPublicKey);

#endif

        if (rsaPrivateKey.Validate(prng, 3) == false)
		{
			wcout << L"Invalid private key!" << endl;
			exit(1);
		}
        if (rsaPublicKey.Validate(prng, 3) == false)
        {
            wcout << L"Invalid public key!" << endl;
			exit(1);
        }
    }
    catch (const Exception &exc)
	{
		wcout << exc.what() << endl;
		exit(1);
	}
    
}

//this function to get the text from the file
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

//save the ciphertext to file
void saveCiphertextToFile(const string &filename,const string &ciphertext)
{
	ofstream file(filename);
	if (file.is_open())
	{
		file << ciphertext;
		file.close();
	}
	else
	{
		wcout << L"Unable to open file!" << endl;
		exit(1);
	}
}

//this function to get the data from the file
string getCiphertextFromFile(string filename)
{
	std::ifstream in_file;
    in_file.open(filename);
    if (!in_file.is_open())
    {
        wcout << L"Can not open file!" << endl;
        exit(1);
    }

    string data;
    string line;
    while (in_file.good())
    {
        getline(in_file, line);
        data += line;
    }
    in_file.close();
    return data;
}

//this function to transform the integer to wstring
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

//this function to show the value of the key
void printKey(RSA::PrivateKey &privateKey, RSA::PublicKey &publicKey)
{
    wcout << "RSA key value" << endl << endl;
    wcout << "Public modulo n = " << in2ws(publicKey.GetModulus()) << endl;
    wcout << endl;
    wcout << "Private prime number p = " << in2ws(privateKey.GetPrime1()) << endl;
    wcout << endl;
    wcout << "Private prime number q = " << in2ws(privateKey.GetPrime2()) << endl;
    wcout << endl;
    wcout << "Public key e = " << in2ws(publicKey.GetPublicExponent()) << endl;
    wcout << endl;
    wcout << "Secret key d = " << in2ws(privateKey.GetPrivateExponent()) << endl;
    wcout << endl;
}

// this function use to encrypt the plaintext
void encrypt(int choiceTypeOfInput)
{
	//declare variables
	AutoSeededRandomPool prng;
	RSA::PrivateKey privateKey;
	RSA::PublicKey publicKey;
	string plaintext;
	wstring wplaintext;

	wcout << L"----------------------------------------------------------------" << endl;
	
	//get the key from file and validate the key
	getKeyFromFileAndValidate(privateKey, publicKey);
	printKey(privateKey, publicKey);

	//get input from file or keyboard

	if(choiceTypeOfInput == 1)
	{

#ifdef _WIN32
		plaintext = getPlaintextFromFile(".\\plaintext.txt");
#elif __linux__
		plaintext = getPlaintextFromFile("./plaintext.txt");
#endif
		wplaintext = s2ws(plaintext);
	}

	else if(choiceTypeOfInput == 2)
	{
		wcout << L"Nhập plaintext: ";
        fflush(stdin);
        getline(wcin, wplaintext);
        plaintext = ws2s(wplaintext);
	}
	else
	{
		wcout << L"Invalid choice!" << endl;
		exit(1);
	}

	//encrypt the plaintext

	string ciphertext;
	double timeCounter = 0;
	
	for(int i = 0; i < nValue; ++i)
	{
		ciphertext.clear();
		double startTime = clock(); //start time
		ciphertext = rsaEncrypt(prng, publicKey, plaintext);
		double endTime = clock(); //end time
		timeCounter += (endTime - startTime);
	}
	wcout << L"----------------------------------------------------------------" << endl;
	wcout << L"This is the RSA encryption!" << endl;
	wcout << L"Plaintext: " << wplaintext << endl;
	wcout << L"Ciphertext: ";
	BeautifulPrinter(ciphertext);
	wcout << L"----------------------------------------------------------------" << endl;
	wcout << L"This is the RSA encryption time counter!" << endl;
	wcout << L"Average time: " << timeCounter / nValue << " ms" << endl;
	//saveCiphertextToFile(".\\rsaoutput3.txt", BeautifulPrinterForFileString(ciphertext));
}

//this function use to decrypt the ciphertext
void decrypt(int choiceTypeOfInput)
{
	//declare variables
	AutoSeededRandomPool prng;
	RSA::PrivateKey privateKey;
	RSA::PublicKey publicKey;
	string ciphertext;
	wstring wciphertext;

	wcout << L"----------------------------------------------------------------" << endl;	
	getKeyFromFileAndValidate(privateKey, publicKey);
	printKey(privateKey, publicKey);
	

	//get input from file or keyboard

	if(choiceTypeOfInput == 1)
	{

#ifdef _WIN32
		ciphertext = getCiphertextFromFile(".\\ciphertext.txt");
#elif __linux__
		ciphertext = getCiphertextFromFile("./ciphertext.txt");
#endif
		wciphertext = s2ws(ciphertext);
		ciphertext = decodeCiphertext(wciphertext);
	}
	else if(choiceTypeOfInput == 2)
	{
		wcout << L"Nhập ciphertext: ";
		fflush(stdin);
		getline(wcin, wciphertext);
		if (wciphertext[wciphertext.size() - 1] != L'H')
    	{
        	wciphertext += L'H';
    	}		
		ciphertext = decodeCiphertext(wciphertext);

	}
	else
	{
		wcout << L"Invalid choice!" << endl;
		exit(1);
	}
	
	//decrypt the ciphertext

	string recovertext;
	double timeCounter = 0;

	for(int i = 0; i < nValue; ++i)
	{
		recovertext.clear();
		double startTime = clock(); //start time
		recovertext = rsaDecrypt(prng, privateKey, ciphertext);
		double endTime = clock(); //end time
		timeCounter += (endTime - startTime);
	}
	wcout << L"----------------------------------------------------------------" << endl;
	wcout << L"This is the RSA decryption!" << endl;
	wcout << L"Ciphertext: ";
	BeautifulPrinter(ciphertext);
	wcout << L"Recovertext: " << s2ws(recovertext) << endl;
	wcout << L"----------------------------------------------------------------" << endl;
	wcout << L"This is the RSA decryption time counter!" << endl;
	wcout << L"Average time: " << timeCounter / nValue << " ms" << endl;
}


int main()
{
	setUpVietnamese();

	int choiceEncDec = selectEncDec();
	int choiceTypeOfInput = selectTypeOfInput();

	switch (choiceEncDec)
	{
	case 1:
		encrypt(choiceTypeOfInput);
		break;
	case 2:
		decrypt(choiceTypeOfInput);
		break;
	default:
		wcout << L"Invalid choice!" << endl;
		exit(1);
		break;
	}

	return 0;
}