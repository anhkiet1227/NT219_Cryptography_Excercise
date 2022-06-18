#include <bits/stdc++.h>

using namespace std;

#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#else
#endif

#include <locale>
using std::wstring_convert;
#include <codecvt>
using std::codecvt_utf8;

#include <cryptopp/cryptlib.h>
#include <cryptopp/sha3.h>
#include <cryptopp/sha.h>
#include <cryptopp/shake.h>

#include <cryptopp/hex.h>
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;

#include <cryptopp/filters.h>
using CryptoPP::Redirector;
using CryptoPP::StringSink;
using CryptoPP::StringSource;

#include <cryptopp/files.h>
using CryptoPP::byte;
using CryptoPP::FileSink;
using CryptoPP::FileSource;

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
	ostringstream oss;
	oss.str("");
	oss.clear();
	oss << t;
	string encoded(oss.str());
	wstring_convert<codecvt_utf8<wchar_t>> towstring;
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

//get message from console
string getMessageFromConsole()
{
    wstring winput;
    wcout << L"Plaintext: ";
    fflush(stdin);
    getline(wcin, winput);
    return ws2s(winput);
}

//get message from file
string getMessageFromFile(string fileName)
{
	ifstream file(fileName);
	string message;
	if (file.is_open())
	{
		string line;
		while (getline(file, line))
		{
			message += line;
		}
		file.close();
	}
	return message;
}

//select hash function
int selectHashFunction()
{
	wcout << L"Select hash function: " << endl;
	wcout << L"1. SHA224" << endl;
	wcout << L"2. SHA256" << endl;
	wcout << L"3. SHA384" << endl;
	wcout << L"4. SHA512" << endl;
	wcout << L"5. SHA3_224" << endl;
	wcout << L"6. SHA3_256" << endl;
	wcout << L"7. SHA3_384" << endl;
	wcout << L"8. SHA3_512" << endl;
	wcout << L"9. SHAKE128" << endl;
	wcout << L"10. SHAKE256" << endl;
	wcout << L"Your choice: ";
	
	int numberOfHashFunction;
	try 
	{
		wcin >> numberOfHashFunction;
		return numberOfHashFunction;
	}
	catch (exception &exc)
	{
		wcout << L"Error in choosing hash function" << endl;
		wcout << L"Error: " << exc.what() << endl;
		exit(1);
	}
}

//choose input from console or file
int selectTypeOfInput()
{
	wcout << L"Select type of input: " << endl;
	wcout << L"1. Console" << endl;
	wcout << L"2. File" << endl;
	wcout << L"Your choice: ";

	int numberOfInput;
	try
	{
		wcin >> numberOfInput;
		return numberOfInput;
	}
	catch (exception &exc)
	{
		wcout << L"Error in choosing type of input" << endl;
		wcout << L"Error: " << exc.what() << endl;
		exit(1);
	}
}

//create hash function
template <class HASH>
string hashFunc(const string &message)
{
    HASH hash;
    string digest;
    hash.Restart();
    hash.Update((const CryptoPP::byte *)message.data(), message.size());
    digest.resize(hash.DigestSize());
    hash.TruncatedFinal((CryptoPP::byte *)&digest[0], digest.size());
    return digest;
}

//create loop hash function
template <class HASH>
double loopingHashFunc(const string &message, string &digest)
{
    double timeCounter = 0.0;
    for (int i = 0; i < nValue; ++i)
    {
        double start = clock();
        digest = hashFunc<HASH>(message);
        double end = clock();
        timeCounter += (end - start) / CLOCKS_PER_SEC;
    }
    return timeCounter;
}

//create shake function
template <class SHAKE>
string shakeFunc(const string &message, int digestSize)
{
	SHAKE hash;
	string digest;
	hash.Restart();
	hash.Update((const CryptoPP::byte *)message.data(), message.size());
    digest.resize(digestSize);
	hash.TruncatedFinal((CryptoPP::byte *)&digest[0], digest.size());
	return digest;
}

//create looping shake function
template <class SHAKE>
double loopingShakeFunc(const string &message, string &digest, int digestSize)
{
	double timeCounter = 0.0;
	for (int i = 0; i < nValue; ++i)
	{
		double start = clock();
		digest = shakeFunc<SHAKE>(message, digestSize);
		double end = clock();
		timeCounter += (end - start) / CLOCKS_PER_SEC;
	}
	return timeCounter;
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

	//declare variables
	string digest = "", message = "";
	string slash = "";
	double timeCounter = 0.0;
	int digestSize;

#ifdef _WIN32
	slash = '\\';
#elif __linux__
	slash = '/';
#endif

	string fileName = "." + slash + "message.txt";

	//selectTypeOfInput
	int typeOfInput = selectTypeOfInput();
	if (typeOfInput == 1)
	{
		message = getMessageFromConsole();
	}
	else if (typeOfInput == 2)
	{
		message = getMessageFromFile(fileName);
	}
	else
	{
		wcout << L"Error in choosing type of input" << endl;
		exit(1);
	}

	//selectHashFunction
	int typeOfHashFunction = selectHashFunction();
	if(typeOfHashFunction == 9 || typeOfHashFunction == 10)
	{
		wcout << L"Enter digest size: ";
		wcin >> digestSize;
	}
	
	switch (typeOfHashFunction)
	{
		case 1:
			timeCounter = loopingHashFunc<CryptoPP::SHA224>(message, digest);
			break;
		
		case 2:
			timeCounter = loopingHashFunc<CryptoPP::SHA256>(message, digest);
			break;
		
		case 3:
			timeCounter = loopingHashFunc<CryptoPP::SHA384>(message, digest);
			break;
		
		case 4:
			timeCounter = loopingHashFunc<CryptoPP::SHA512>(message, digest);
			break;
		
		case 5:
			timeCounter = loopingHashFunc<CryptoPP::SHA3_224>(message, digest);
			break;
		
		case 6:
			timeCounter = loopingHashFunc<CryptoPP::SHA3_256>(message, digest);
			break;
		
		case 7:
			timeCounter = loopingHashFunc<CryptoPP::SHA3_384>(message, digest);
			break;
		
		case 8:
			timeCounter = loopingHashFunc<CryptoPP::SHA3_512>(message, digest);
			break;
		
		case 9:
			timeCounter = loopingShakeFunc<CryptoPP::SHAKE128>(message, digest, digestSize);
			break;
		
		case 10:
			timeCounter = loopingShakeFunc<CryptoPP::SHAKE256>(message, digest, digestSize);
			break;
		
	}
	wcout << L"----------------------------------------------------------------" << endl;
	wcout << L"Message: " << s2ws(message) << endl;
	wcout << L"Digest: ";
	BeautifulPrinter(digest);
	timeCounter = timeCounter * 1000 / nValue;
	wcout << L"TimeCounter: " << timeCounter << L" ms" << endl;

	return 0;
}