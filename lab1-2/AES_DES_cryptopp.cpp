#include <bits/stdc++.h>
using std::ifstream;
using std::ofstream;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include <iostream>
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#endif
using std::cerr;
using std::cin;
using std::cout;
using std::endl;
using std::getline;
using std::wcin;
using std::wcout;
using std::wstring;

#include <limits>

#include <string>
using std::string;

#include <codecvt>
#include <locale>

#include <cstdlib>
using std::exit;

#include "cryptopp/cryptlib.h"
using CryptoPP::AAD_CHANNEL;
using CryptoPP::BufferedTransformation;
using CryptoPP::DEFAULT_CHANNEL;
using CryptoPP::Exception;

#include "cryptopp/hex.h"
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;

#include "cryptopp/filters.h"
using CryptoPP::AuthenticatedDecryptionFilter;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::Redirector;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;

#include "cryptopp/des.h"
using CryptoPP::DES;

#include "cryptopp/aes.h"
using CryptoPP::AES;

#include "cryptopp/modes.h"
using CryptoPP::CBC_Mode;
using CryptoPP::CFB_Mode;
using CryptoPP::CTR_Mode;
using CryptoPP::ECB_Mode;
using CryptoPP::OFB_Mode;

#include "cryptopp/xts.h"
using CryptoPP::XTS;

#include "cryptopp/ccm.h"
using CryptoPP::CCM;

#include "cryptopp/gcm.h"
using CryptoPP::GCM;
//using CryptoPP::GCM_TablesOption;

#include "cryptopp/secblock.h"
using CryptoPP::SecByteBlock;

#include "cryptopp/files.h"
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include <assert.h>

#define nValue 10000

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

// convert byteBlock to hex wstring cryptopp::byte
void BeautifulPrinter(SecByteBlock byteBlock)
{
	string encodedCode = "";
	StringSource(byteBlock, byteBlock.size(), true,
				 new HexEncoder(
					 new StringSink(encodedCode)));
	wstring wstr = s2ws(encodedCode);
	wcout << wstr << endl;
}

//BeautifulPrinter for file
wstring BeautifulPrinterForFile(SecByteBlock byteBlock)
{
	string encodedCode = "";
	StringSource(byteBlock, byteBlock.size(), true,
				 new HexEncoder(
					 new StringSink(encodedCode)));
	wstring wstr = s2ws(encodedCode);
	return wstr;
}

// convert byteArray to hex wstring using cryptopp::byte
void BeautifulPrinter(CryptoPP::byte *byteArray)
{
	string encodedCode = "";
	StringSource(byteArray, sizeof(byteArray), true,
				 new HexEncoder(
					 new StringSink(encodedCode)));
	wstring wstr = s2ws(encodedCode);
	wcout << wstr << endl;
}

//beautifulPrinter for file
wstring BeautifulPrinterForFile(CryptoPP::byte *byteArray)
{
	string encodedCode = "";
	StringSource(byteArray, sizeof(byteArray), true,
				 new HexEncoder(
					 new StringSink(encodedCode)));
	wstring wstr = s2ws(encodedCode);
	return wstr;
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

//beautifulPrinter for file
wstring BeautifulPrinterForFile(string byteString)
{
	string encodedCode = "";
	StringSource(byteString, true,
				 new HexEncoder(
					 new StringSink(encodedCode)));
	wstring wstr = s2ws(encodedCode);
	return wstr;
}

// Vietnamese language support
void setUpVietnamese()
{
#ifdef _WIN32
	_setmode(_fileno(stdin), _O_U16TEXT);
	_setmode(_fileno(stdout), _O_U16TEXT);
#elif __linux__
	setlocale(LC_ALL, "");
#endif
}

// function select Scheme
int selectScheme()
{
	int schemeNumber;
	wcout << L"Chọn scheme: " << endl;
	wcout << L"1. DES" << endl;
	wcout << L"2. AES" << endl;
	wcout << L"Lựa chọn: ";
	try
	{
		wcin >> schemeNumber;
		if (schemeNumber != 1 && schemeNumber != 2)
		{
			wcout << L"Lựa chọn không hợp lệ" << endl;
			exit(1);
		}
		return schemeNumber;
	}
	catch (const std::exception &e)
	{
		wcout << L"Lựa chọn không hợp lệ" << endl;
		exit(1);
	}
}

// function select Mode
int selectMode(bool check_AES)
{
	// both AES and DES have same mode
	wcout << L"Chọn Mode: " << endl;
	wcout << L"1. ECB" << endl;
	wcout << L"2. CBC" << endl;
	wcout << L"3. CFB" << endl;
	wcout << L"4. OFB" << endl;
	wcout << L"5. CTR" << endl;

	// AES mode
	if (check_AES)
	{
		wcout << L"6. XTS" << endl;
		wcout << L"7. GCM" << endl;
		wcout << L"8. CCM" << endl;
	}
	wcout << L"Lựa chọn: ";
	int modeNumber;
	try
	{
		wcin >> modeNumber;
		if (modeNumber < 1 || (modeNumber > 8 && check_AES) || (modeNumber > 5 && !check_AES))
		{
			wcout << L"Lựa chọn không hợp lệ" << endl;
			exit(1);
		}
		return modeNumber;
	}
	catch (const std::exception &e)
	{
		wcout << L"Lựa chọn không hợp lệ" << endl;
		exit(1);
	}
}

// function select key size for AES
int selectKeySize(int modeNumber)
{
	const int keySizeArray[] = {16, 24, 32, 64};
	wcout << L"Chọn key size: " << endl;
	if (modeNumber != 6)
	{
		wcout << L"1. 128 bits default" << endl;
		wcout << L"2. 192 bits" << endl;
		wcout << L"3. 256 bits" << endl;
	}
	else
	{
		wcout << L"1. 256 bits" << endl;
		wcout << L"2. 512 bits" << endl;
	}
	wcout << L"Lựa chọn: ";
	int keySizeNumber;
	try
	{
		wcin >> keySizeNumber;
		if (modeNumber != 6 && keySizeNumber >= 1 && keySizeNumber <= 3)
		{
			return keySizeArray[keySizeNumber - 1];
		}
		else if (modeNumber == 6 && keySizeNumber >= 1 && keySizeNumber <= 2)
		{
			return keySizeArray[keySizeNumber + 1];
		}
		else 
		{
			wcout << L"Lựa chọn không hợp lệ" << endl;
			exit(1);
		}
	}
	catch (const std::exception &e)
	{
		wcout << L"Lựa chọn không hợp lệ" << endl;
		exit(1);
	}
}

// function select Iv size
int selectIVSize(int modeNumber)
{
	wcout << L"Chọn IV size: " << endl;
	wcout << L"1. Tự chọn" << endl;
	wcout << L"2. Mặc định" << endl;
	wcout << L"Lựa chọn: ";
	int IVSizeNumber, optionNumber;
	try
	{
		wcin >> optionNumber;
		if (optionNumber < 1 or optionNumber > 2)
		{
			wcout << L"Lựa chọn không hợp lệ" << endl;
			exit(1);
		}
		if (optionNumber == 1)
		{
			if (modeNumber == 7)
			{
				wcout << L"Chọn IV size: " << endl;
				wcin >> IVSizeNumber;
			}
			else if (modeNumber == 8)
			{
				wcout << L"Chọn IV size [7,13]: " << endl;
				wcin >> IVSizeNumber;
				if (IVSizeNumber < 7 || IVSizeNumber > 13)
				{
					wcout << L"Lựa chọn không hợp lệ" << endl;
					exit(1);
				}
			}
		}
		else if (optionNumber == 2)
		{
			if (modeNumber == 7)
			{
				IVSizeNumber = AES::BLOCKSIZE;
			}
			else if (modeNumber == 8)
			{
				IVSizeNumber = 8;
			}
		}
	}
	catch (const std::exception &e)
	{
		wcout << L"Lựa chọn không hợp lệ" << endl;
		exit(1);
	}
	return IVSizeNumber;
}

// get data from mode 7 and mode 8: CCM mode and GCM mode
string getAuthData()
{
	wstring wGetData = L"";
	wcout << L"Nhập dữ liệu: ";
	fflush(stdin);
#ifdef __linux__
	getline(wcin, wGetData);
	getline(wcin, wGetData);
#endif
	getline(wcin, wGetData);
	string sGetData = ws2s(wGetData);
	return sGetData;
}

// function to get data from console
void getDataFromConsole(SecByteBlock &block, int blockSize, wstring type)
{

	try
	{
		// get data from the console
		wstring wDataInput;
		wcout << L"Nhập dữ liệu " << type << L": ";
		fflush(stdin);
		getline(wcin, wDataInput);
		string sDataInput = ws2s(wDataInput);

		// convert to byteBlock
		StringSource ss(sDataInput, false);
		CryptoPP::ArraySink as(block, blockSize);
		ss.Detach(new Redirector(as));
		ss.Pump(blockSize);
	}
	catch (const std::exception &e)
	{
		wcout << L"Lỗi nhập dữ liệu" << endl;
		exit(1);
	}
}

// generate key and IV based on user option (screen or file or random)
void generateSecByteBlock(SecByteBlock &block, int &blockSize, wstring type, int scheme)
{
	wcout << L"Nhập " << type << L" random hay đọc từ file: \n";
	wcout << L"1. Nhập" << endl;
	wcout << L"2. Random" << endl;
	wcout << L"3. File" << endl;
	wcout << L"Lựa chọn: ";
	int optionNumber;
	try
	{
		wcin >> optionNumber;
		if (optionNumber < 1 || optionNumber > 3)
		{
			wcout << L"Lựa chọn không hợp lệ" << endl;
			exit(1);
		}
		else if (optionNumber == 1)
		{
			block = SecByteBlock(blockSize);
			getDataFromConsole(block, blockSize, type);
		}
		else if (optionNumber == 2)
		{
			AutoSeededRandomPool prng;
			block = SecByteBlock(blockSize);
			prng.GenerateBlock(block, blockSize);
		}
		else if (optionNumber == 3)
		{
			block = SecByteBlock(blockSize);
			if (scheme == 1 && type == L"key")
			{
#ifdef _WIN32
				FileSource fs(".\\des_key.key", false);
				CryptoPP::ArraySink as(block, blockSize);
				fs.Detach(new Redirector(as));
				fs.Pump(blockSize);
#elif __linux__
				FileSource fs("./des_key.key", false);
				CryptoPP::ArraySink as(block, blockSize);
				fs.Detach(new Redirector(as));
				fs.Pump(blockSize);
#endif
			}
			else if (scheme == 1 && type == L"iv")
			{
#ifdef _WIN32
				FileSource fs(".\\des_iv.key", false);
				CryptoPP::ArraySink as(block, blockSize);
				fs.Detach(new Redirector(as));
				fs.Pump(blockSize);
#elif __linux__
				FileSource fs("./des_key.key", false);
				CryptoPP::ArraySink as(block, blockSize);
				fs.Detach(new Redirector(as));
				fs.Pump(blockSize);
#endif
			}
			else if (scheme == 2 && type == L"key")
			{
#ifdef _WIN32
				FileSource fs(".\\aes_key.key", false);
				CryptoPP::ArraySink as(block, blockSize);
				fs.Detach(new Redirector(as));
				fs.Pump(blockSize);
#elif __linux__
				FileSource fs("./aes_key.key", false);
				CryptoPP::ArraySink as(block, blockSize);
				fs.Detach(new Redirector(as));
				fs.Pump(blockSize);
#endif
			}
			else if (scheme == 2 && type == L"iv")
			{
#ifdef _WIN32
				FileSource fs(".\\aes_iv.key", false);
				CryptoPP::ArraySink as(block, blockSize);
				fs.Detach(new Redirector(as));
				fs.Pump(blockSize);
#elif __linux__
				FileSource fs("./aes_iv.key", false);
				CryptoPP::ArraySink as(block, blockSize);
				fs.Detach(new Redirector(as));
				fs.Pump(blockSize);
#endif
			}
			else
			{
#ifdef _WIN32
				FileSource fs(".\\aes_iv.key", false);
				CryptoPP::ArraySink as(block, blockSize);
				fs.Detach(new Redirector(as));
				fs.Pump(blockSize);
#elif __linux__
				FileSource fs("./aes_iv.key", false);
				CryptoPP::ArraySink as(block, blockSize);
				fs.Detach(new Redirector(as));
				fs.Pump(blockSize);
#endif
			}
		}
		else
		{
			wcout << L"Lựa chọn không hợp lệ" << endl;
			exit(1);
		}
	}
	catch (const std::exception &e)
	{
		wcout << L"Lựa chọn không hợp lệ" << endl;
		exit(1);
	}
}
// template function to encrypt of many types of operation modes
//  mode: 'm<DES>::encrypt': m is the mode, DES is the algorithm
template <class mode>
void encrypt(const string &plaintext, mode &enc, string &ciphertext)
{
	ciphertext.clear();
	try
	{
		// stringsourece pineline get plaintext
		// StreamTransformationFilter performs the encryption
		// string sink pipeline get ciphertext
		StringSource(plaintext, true,
					 new StreamTransformationFilter(enc,
													new StringSink(ciphertext)));
	}
	catch (const std::exception &e)
	{
		wcout << e.what() << endl;
		exit(1);
	}
}

// template function to decrypt of many types of operation modes
//  mode: 'm<DES>::decrypt': m is the mode, DES is the algorithm
template <class mode>
void decrypt(const string &ciphertext, mode &dec, string &plaintext)
{
	plaintext.clear();
	try
	{
		// stringsourece pineline get ciphertext
		// StreamTransformationFilter performs the decryption
		// string sink pipeline get plaintext
		StringSource(ciphertext, true,
					 new StreamTransformationFilter(dec,
													new StringSink(plaintext)));
	}
	catch (const std::exception &e)
	{
		wcout << L"Lỗi giải mã" << endl;
		exit(1);
	}
}

// function to encrypt and decrypt and get the time of each operation
template <class encryption, class decryption>
double *encrypt_decrypt(const SecByteBlock &key, string plaintext, string &ciphertext, string &recovertext)
{
	int startTimeEnc = clock(); // get the start time of encryption
	// start encryption
	encryption enc;
	try
	{
		enc.SetKey(key, key.size());
	}
	catch (const std::exception &e)
	{
		wcout << L"vitri1";
		wcout << e.what() << '\n';
		exit(1);
	}
	encrypt<encryption>(plaintext, enc, ciphertext);
	// end encryption
	int endTimeEnc = clock(); // get the end time of encryption

	int startTimeDec = clock(); // get the start time of decryption
	// start decryption
	decryption dec;
	try
	{
		dec.SetKey(key, key.size());
	}
	catch (const std::exception &e)
	{
		wcout << L"vitri2";
		wcout << e.what() << '\n';
		exit(1);
	}
	decrypt<decryption>(ciphertext, dec, recovertext);
	// end decryption
	int endTimeDec = clock(); // get the end time of decryption

	// get the time
	double *time = new double[2];
	time[0] = (double)(endTimeEnc - startTimeEnc) / CLOCKS_PER_SEC * 1000;
	time[1] = (double)(endTimeDec - startTimeDec) / CLOCKS_PER_SEC * 1000;
	return time;
}

// function to encrypt and decrypt and get the time of each operation
//  iv is the initialization vector
// the time of the operation is the same as the time of the encryption and decryption
template <class encryption, class decryption>
double *encrypt_decrypt_iv(const SecByteBlock &key, const SecByteBlock &iv, string plaintext, string &ciphertext, string &recovertext)
{
	int startTimeEnc = clock(); // get the start time of encryption
	// start encryption
	encryption enc;
	try
	{
		
		enc.SetKeyWithIV(key, key.size(), iv);
	}
	catch (const std::exception &e)
	{
		wcout << L"vitri3";
		wcout << e.what() << '\n';
		exit(1);
	}
	encrypt<encryption>(plaintext, enc, ciphertext);
	// end encryption
	int endTimeEnc = clock(); // get the end time of encryption

	int startTimeDec = clock(); // get the start time of decryption
	// start decryption
	decryption dec;
	try
	{
		dec.SetKeyWithIV(key, key.size(), iv, iv.size());
	}
	catch (const std::exception &e)
	{
		wcout << L"vitri4";
		wcout << e.what() << '\n';
		exit(1);
	}
	decrypt<decryption>(ciphertext, dec, recovertext);
	// end decryption
	int endTimeDec = clock(); // get the end time of decryption

	// get the time
	double *time = new double[2];
	time[0] = (double)(endTimeEnc - startTimeEnc) / CLOCKS_PER_SEC * 1000;
	time[1] = (double)(endTimeDec - startTimeDec) / CLOCKS_PER_SEC * 1000;
	return time;
}

// encrypt decrypt with authentication code
// the time of the operation is the same as the time of the encryption and decryption
template <class encryption, class decryption>
double *encrypt_decrypt_auth(const SecByteBlock &key, const SecByteBlock &iv, string plaintext, string auth, string &ciphertext, string &recovertext, string &recoverauth)
{
	ciphertext.clear();
	recovertext.clear();

	int startTimeEnc = clock(); // get the start time of encryption
	const int tagSize = 8;
	// start encryption
	
	try
	{
		encryption enc;
		// attach key and iv
		enc.SetKeyWithIV(key, key.size(), iv, iv.size());
		// require for the CCM (not GCM)
		enc.SpecifyDataLengths(auth.size(), plaintext.size(), 0);

		AuthenticatedEncryptionFilter aef(enc, new StringSink(ciphertext), false, tagSize);

		// put authenticated data to the channel
		aef.ChannelPut(AAD_CHANNEL, (const CryptoPP::byte *)auth.data(), auth.size());
		aef.ChannelMessageEnd(AAD_CHANNEL);
		// put plaintext to the channel
		aef.ChannelPut(DEFAULT_CHANNEL, (const CryptoPP::byte *)plaintext.data(), plaintext.size());
		aef.ChannelMessageEnd(DEFAULT_CHANNEL);
	}
	catch (const std::exception &e)
	{
		wcout << L"vi tri 5";
		wcout << e.what() << '\n';
		exit(1);
	}
	// end encryption

	int endTimeEnc = clock(); // get the end time of encryption
	// start decryption
	int startTimeDec = clock(); // get the start time of decryption
	
	try
	{
		decryption dec;
		// split the ciphertext into two parts: macValue and encrypted data
		string encryptedData = ciphertext.substr(0, ciphertext.size() - tagSize);
		string macValue = ciphertext.substr(ciphertext.size() - tagSize);
		recoverauth = auth;

		// attach key and iv
		dec.SetKeyWithIV(key, key.size(), iv, iv.size());
		// require for the CCM (not GCM)
		dec.SpecifyDataLengths(recoverauth.size(), encryptedData.size(), 0);

		AuthenticatedDecryptionFilter daf(dec, NULL,
										  AuthenticatedDecryptionFilter::MAC_AT_BEGIN |
											  AuthenticatedDecryptionFilter::THROW_EXCEPTION,
										  tagSize);

		daf.ChannelPut(DEFAULT_CHANNEL, (const CryptoPP::byte *)macValue.data(), macValue.size());
		daf.ChannelPut(AAD_CHANNEL, (const CryptoPP::byte *)auth.data(), auth.size());
		daf.ChannelPut(DEFAULT_CHANNEL, (const CryptoPP::byte *)encryptedData.data(), encryptedData.size());

		daf.ChannelMessageEnd(AAD_CHANNEL);
		daf.ChannelMessageEnd(DEFAULT_CHANNEL);

		// check data integrity
		bool isValid = false;
		isValid = daf.GetLastResult();
		assert(true == isValid);

		// retrive confidential data
		daf.SetRetrievalChannel(DEFAULT_CHANNEL);
		size_t len = (size_t)daf.MaxRetrievable();
		recovertext.resize(len);
		if (len > 0)
			daf.Get((CryptoPP::byte *)recovertext.data(), len);
	}
	catch (const std::exception &e)
	{
		wcout << L"vi tri 6";
		wcout << e.what() << '\n';
		exit(1);
	}
	// end decryption

	int endTimeDec = clock(); // get the end time of decryption

	// get the time
	double *time = new double[2];
	time[0] = (double)(endTimeEnc - startTimeEnc) / CLOCKS_PER_SEC * 1000;
	time[1] = (double)(endTimeDec - startTimeDec) / CLOCKS_PER_SEC * 1000;
	return time;
}

// des mode operation dont use iv
// give the total time of time of encryption and decryption for 10000 times
template <class encryption, class decryption>
double *loopnoniv(const SecByteBlock &key, string plaintext, string &ciphertext, string &recovertext)
{
	double *sum = new double[2];
	double *time = NULL;
	sum[0] = 0;
	sum[1] = 0;

	for (int i = 0; i < nValue; i++)
	{
		time = encrypt_decrypt<encryption, decryption>(key, plaintext, ciphertext, recovertext);
		sum[0] += time[0];
		sum[1] += time[1];
	}
	delete[] time;
	return sum;
}

// des mode operation use iv
// give the total time of time of encryption and decryption for 10000 times
template <class encryption, class decryption>
double *loopiv(const SecByteBlock &key, const SecByteBlock &iv, string plaintext, string &ciphertext, string &recovertext)
{
	double *sum = new double[2];
	double *time = NULL;
	sum[0] = 0;
	sum[1] = 0;

	for (int i = 0; i < nValue; i++)
	{
		time = encrypt_decrypt_iv<encryption, decryption>(key, iv, plaintext, ciphertext, recovertext);
		sum[0] += time[0];
		sum[1] += time[1];
	}
	delete[] time;
	return sum;
}



//mode auth for mode CCM and GCM
// give the total time of time of encryption and decryption for 10000 times
template <class encryption, class decryption>
double *loopauth(const SecByteBlock &key, const SecByteBlock &iv, string plaintext, string auth, string &ciphertext, string &recovertext, string &recoverauth)
{
	double *sum = new double[2];
	double *time = NULL;
	sum[0] = 0;
	sum[1] = 0;

	for (int i = 0; i < nValue; i++)
	{
		time = encrypt_decrypt_auth<encryption, decryption>(key, iv, plaintext, auth, ciphertext, recovertext, recoverauth);
		sum[0] += time[0];
		sum[1] += time[1];
	}
	delete[] time;
	return sum;
}

// get plaintext from file
string getPlaintext(string filename)
{
	string plaintext;
	ifstream infile(filename.c_str());
	if (!infile)
	{
		wcout << "open file error" << endl;
		exit(1);
	}
	string line;
	while (getline(infile, line))
	{
		plaintext += line;
	}
	infile.close();
	return plaintext;
}

// main function
int main(int argc, char *argv[])
{
	// setUp Vietnamese language
	setUpVietnamese();
	wcout << L"Lab 1-2" << endl;

	// declare variables
	AutoSeededRandomPool prng;
	CryptoPP::SecByteBlock key;
	CryptoPP::SecByteBlock iv;
	string plaintext, ciphertext, recovertext, auth, recoverauth;
	wstring wplaintext, wciphertext, wrecovertext;
	double *time = NULL;
	int keySize, ivSize, mode;

	// get plaintext from keyboard or fileName
	wcout << L"Chọn loại lấy file: " << endl;
	wcout << L"1. Từ bàn phím" << endl;
	wcout << L"2. Từ file" << endl;
	wcout << L"Lựa chọn: ";
	int choice;
	wcin >> choice;
	if (choice == 1)
	{
		// get the plaintext
		wcout << L"Nhập plaintext: ";
		wcin >> wplaintext;
		//getline(wcin, wplaintext);
		wcin.ignore();
		// convert plaintext to string
		plaintext = ws2s(wplaintext);
	}
	else if (choice == 2)
	{
		// get the plaintext from file
		plaintext = getPlaintext("testcase1.txt");
		wplaintext = s2ws(plaintext);
	}
	else
	{
		wcout << L"Nhập sai" << endl;
		exit(1);
	}

	// select scheme
	int scheme = selectScheme();

	// select mode

	if (scheme == 1)
	{
		mode = selectMode(false);
	}
	else if (scheme == 2)
	{
		mode = selectMode(true);
	}

	if (mode == 7 || mode == 8)
	{
		auth = getAuthData();
	}

	// des
	if (scheme == 1)
	{
		// generate key use random, screen, file
		keySize = DES::DEFAULT_KEYLENGTH;
		generateSecByteBlock(key, keySize, L"key", scheme);
		if (mode > 1)
		{
			// generate iv use random, screen, file
			ivSize = DES::BLOCKSIZE;
			generateSecByteBlock(iv, ivSize, L"iv", scheme);

			// write iv to file
#ifdef _WIN32
			StringSource ssiv(iv, iv.size(), true,
							  new FileSink(".\\des_iv.key"));
#elif __linux__
			StringSource ssiv(iv, iv.size(), true,
							  new FileSink("./des_iv.key"));
#endif
		}

// write key to file
#ifdef _WIN32
		StringSource sskey(key, key.size(), true,
						   new FileSink(".\\des_key.key"));
#elif __linux__
		StringSource sskey(key, key.size(), true,
						   new FileSink("./des_key.key"));
#endif
		switch (mode) // encrypt on mode
		{
		case 1:
			time = loopnoniv<ECB_Mode<DES>::Encryption, ECB_Mode<DES>::Decryption>(key, plaintext, ciphertext, recovertext);
			break;
		case 2:
			time = loopiv<CBC_Mode<DES>::Encryption, CBC_Mode<DES>::Decryption>(key, iv, plaintext, ciphertext, recovertext);
			break;
		case 3:
			time = loopiv<CFB_Mode<DES>::Encryption, CFB_Mode<DES>::Decryption>(key, iv, plaintext, ciphertext, recovertext);
			break;
		case 4:
			time = loopiv<OFB_Mode<DES>::Encryption, OFB_Mode<DES>::Decryption>(key, iv, plaintext, ciphertext, recovertext);
			break;
		case 5:
			time = loopiv<CTR_Mode<DES>::Encryption, CTR_Mode<DES>::Decryption>(key, iv, plaintext, ciphertext, recovertext);
			break;
		}
	}
	// aes
	else if (scheme == 2)
	{
		// select keySize
		keySize = selectKeySize(mode);
		// check keySize
		if (keySize == 64 && mode != 6)
		{
			wcout << L"keySize 64 bit không thể dùng cho mode này" << endl;
			exit(1);
		}

		// generate key use random, screen, file
		generateSecByteBlock(key, keySize, L"key", scheme);

		// generate iv
		if (mode > 1)
		{
			if (mode == 7 || mode == 8)
			{
				ivSize = selectIVSize(mode);
			}
			else
			{
				ivSize = AES::BLOCKSIZE;
			}
			generateSecByteBlock(iv, ivSize, L"iv", scheme);

			// write iv to file
#ifdef _WIN32
			StringSource ssiv(iv, iv.size(), true, new FileSink(".\\aes_iv.key"));
#elif __linux__
			StringSource ssiv(iv, iv.size(), true, new FileSink("./aes_iv.key"));
#endif
		}

		// write key to file
#ifdef _WIN32
		StringSource sskey(key, key.size(), true, new FileSink(".\\aes_key.key"));
#elif __linux__
		StringSource sskey(key, key.size(), true, new FileSink("./aes_key.key"));
#endif

		switch (mode) // encrypt on mode
		{
		case 1:
			time = loopnoniv<ECB_Mode<AES>::Encryption, ECB_Mode<AES>::Decryption>(key, plaintext, ciphertext, recovertext);
			break;
		case 2:
			time = loopiv<CBC_Mode<AES>::Encryption, CBC_Mode<AES>::Decryption>(key, iv, plaintext, ciphertext, recovertext);
			break;
		case 3:
			time = loopiv<CFB_Mode<AES>::Encryption, CFB_Mode<AES>::Decryption>(key, iv, plaintext, ciphertext, recovertext);
			break;
		case 4:
			time = loopiv<OFB_Mode<AES>::Encryption, OFB_Mode<AES>::Decryption>(key, iv, plaintext, ciphertext, recovertext);
			break;
		case 5:
			time = loopiv<CTR_Mode<AES>::Encryption, CTR_Mode<AES>::Decryption>(key, iv, plaintext, ciphertext, recovertext);
			break;
		case 6:
			time = loopiv<XTS_Mode<AES>::Encryption, XTS_Mode<AES>::Decryption>(key, iv, plaintext, ciphertext, recovertext);
			break;
		case 7:
			time = loopauth<GCM<AES>::Encryption, GCM<AES>::Decryption>(key, iv, plaintext, auth, ciphertext, recovertext, recoverauth);
			break;
		case 8:
			time = loopauth<CCM<AES>::Encryption, CCM<AES>::Decryption>(key, iv, plaintext, auth, ciphertext, recovertext, recoverauth);
			break;
		}
	}
	else
	{
		wcout << L"scheme không hợp lệ" << endl;
		exit(1);
	}

	// display sample
	wcout << L"--------------------------------------------------------------------------------" << endl;
	wcout << L"This is the result" << endl
		  << endl;
	wcout << L"plaintext: " << wplaintext << endl;
	wcout << L"key: ";
	BeautifulPrinter(key);
	if (mode > 1)
	{
		wcout << L"iv: ";
		BeautifulPrinter(iv);
	}
	wcout << L"ciphertext: ";
	BeautifulPrinter(ciphertext);
	wcout << L"recovertext: " << s2ws(recovertext) << endl;
	if (mode == 7 || mode == 8)
	{
		wcout << L"recoverauth: " << s2ws(recoverauth) << endl;
	}

	// display time
	wcout << L"--------------------------------------------------------------------------------" << endl;
	wcout << L"Time counter" << endl
		  << endl;
	wcout << L"time encrypt 10000: " << time[0] << " ms" << endl;
	wcout << L"average encrypt time: " << time[0] / nValue << " ms" << endl;
	wcout << endl;
	wcout << L"time decrypt 10000: " << time[1] << " ms" << endl;
	wcout << L"average decrypt time: " << time[1] / nValue << " ms" << endl;
	wcout << L"--------------------------------------------------------------------------------" << endl;

	wcout << L"Ghi dữ liệu vào file" << endl;
	wcout << L"1 Có" << endl;
	wcout << L"2 Không" << endl;
	wcout << L"Lựa chọn: ";
	int choiceFile;
	wcin >> choiceFile;
	if (choiceFile == 1)
	{
		ofstream outFile;
		outFile.open("./data.txt");
		outFile << "This is the result" << endl << endl;
		outFile << "plaintext: " << plaintext << endl;
		string tmpkey = ws2s(BeautifulPrinterForFile(key));
		outFile << "key: " << tmpkey << endl;
		if (mode > 1)
		{
			string tmpiv = ws2s(BeautifulPrinterForFile(iv));
			outFile << "iv: " << tmpiv << endl;
		}
		string tmpCiphertext = ws2s(BeautifulPrinterForFile(ciphertext));
		outFile << "ciphertext: " << tmpCiphertext << endl;
		outFile << "recovertext: " << recovertext << endl;
		if (mode == 7 || mode == 8)
		{
			outFile << "recoverauth: " << recoverauth << endl;
		}
		outFile << "--------------------------------------------------------------------------------" << endl;
		outFile << "Time counter" << endl << endl;
		outFile << "time encrypt 10000: " << time[0] << " ms" << endl;
		outFile << "average encrypt time: " << time[0] / nValue << " ms" << endl;
		outFile << endl;
		outFile << "time decrypt 10000: " << time[1] << " ms" << endl;
		outFile << "average decrypt time: " << time[1] / nValue << " ms" << endl;
		outFile << "--------------------------------------------------------------------------------" << endl;
		outFile.close();
		wcout << L"Ghi file thành công" << endl;			
	}
	else
	{
		wcout << L"Không ghi dữ liệu vào file" << endl;
	}

	delete[] time;

	return 0;
}
