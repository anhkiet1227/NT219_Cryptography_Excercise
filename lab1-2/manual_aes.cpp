#include <bits/stdc++.h>
using std::wstring;
using std::wstring_convert;

#include <math.h>

#include <iostream>
#include <codecvt>
#include <locale>
#include <vector>
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#endif

#include <string>
#include <iomanip>

//this is the constant used in the AES algorithm

#include "constantaes.hpp"

using namespace std;

//constant and array for AES encryption and decryption

extern const unsigned char gmultab[256][256];
extern const unsigned char sbox[16][16];
extern const unsigned char inv_sbox[16][16];

const unsigned char shift_row_routine[4] = {0, 1, 2, 3};

const unsigned char const_mul_mat[4][4] = {
    2, 3, 1, 1,
    1, 2, 3, 1,
    1, 1, 2, 3,
    3, 1, 1, 2};

const unsigned char const_inv_mul_mat[4][4] = {
    0x0e, 0x0b, 0x0d, 0x09,
    0x09, 0x0e, 0x0b, 0x0d,
    0x0d, 0x09, 0x0e, 0x0b,
    0x0b, 0x0d, 0x09, 0x0e};

const unsigned char round_constants[4][10] = {
    0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};

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

//multiple 2 bytes depend on GF(2^8)
unsigned char multipleGF2Bytes(unsigned char w1, unsigned char w2)
{
    return gmultab[w1][w2];
}

//get 4 first bit value 
unsigned char get4FirstBit(unsigned char value)
{
    return value >> 0x4;
}

//get 4 last bit value
unsigned char get4LastBit(unsigned char value)
{
    return value & 0xF;
}

//convert the string to block
vector<vector<unsigned char>> convertStringToBlock(string str)
{
    vector<vector<unsigned char>> block(4);
    int currentRow = 0;
    
    for(unsigned char c : str)
    {
        block[currentRow].push_back(c);
        currentRow = (currentRow + 1) % 4;
    }

    return block;
}

//convert the block to string
string convertBlockToString(const vector<vector<unsigned char>> &block)
{
    string str = "";
    
    for (int i = 0; i < block[0].size(); ++i)
    {
        for (int j = 0; j < 4; ++j)
        {
            str += block[j][i];
        }
            
    }     
    return str;
}

//print the maxtrix
void printMatrix(const vector<vector<unsigned char>> &block)
{
    for (int i = 0; i < block.size(); ++i)
    {
        for (int j = 0; j < block[i].size(); ++j)
        {
            wcout << setfill(L'0') << setw(2) << hex << uppercase << (unsigned int)block[i][j] << " ";
        }
        wcout << endl;
    }
        
}

//print hex string
void printHexString(const vector<vector<unsigned char>> &block)
{
    for (int column = 0; column < block[0].size(); ++column)
    {
        for (int row = 0; row < 4; ++row)
        {
            wcout << setfill(L'0') << setw(2) << hex << uppercase << (unsigned int)block[row][column];
        }
    }
    wcout << endl;
}

//slitting the block to 16 byte from block
vector<vector<unsigned char>> split(const vector<vector<unsigned char>> &block, unsigned int n)
{
    vector<vector<unsigned char>> subBlock(4);
    for (int j = 0; j < 4; ++j)
    {
        for (int i = 0; i < 4; ++i)
        {
            subBlock[i].push_back(block[i][n + j]);
        }
    }      
            
    return subBlock;
}

//shift a row circularly for shift amount times
vector<unsigned char> &cirShiftRow(vector<unsigned char> &row, unsigned char amount)
{
    while (amount--)
    {
        row.push_back(*row.begin());
        row.erase(row.begin());
    }
    return row;
}

//xor two two-direction vector
vector<vector<unsigned char>> xorTwoVector(vector<vector<unsigned char>> &a, vector<vector<unsigned char>> &b)
{
    vector<vector<unsigned char>> result(a.size());

    for (int i = 0; i < result.size(); ++i)
    {
        for (int j = 0; j < a[i].size(); ++j)
        {
            result[i].push_back(a[i][j] ^ b[i][j]);
        }
    }      
            
    return result;
}

//rotate word circularly for shift amount times
vector<vector<unsigned char>> &rotateWord(vector<vector<unsigned char>> &block)
{
    unsigned char tmp;

    for (int row = 0; row < block.size(); ++row)
    {
        if (row < block.size() - 1)
        {
            if (row == 0)
            {
                tmp = block[row][0];
            }
            block[row][0] = block[row + 1][0];
        }
        else
        {
            block[row][0] = tmp;
        }
    }
    
    return block;
}

//add null padding to the block if it is not multiple of 16
vector<vector<unsigned char>> &addPadding(vector<vector<unsigned char>> &block)
{
    int maxSize = max(max(block[0].size(), block[1].size()), max(block[2].size(), block[3].size()));
    
    while (maxSize % 4 > 0)
    {
        ++maxSize;
    }        
    
    for (int i = 0; i < 4; ++i)
    {
        while(block[i].size() < maxSize)
        {
            block[i].push_back(0);
        }
    }       
    
    return block;
}

//remove null padding from the block
vector<vector<unsigned char>> &removePadding(vector<vector<unsigned char>> &block)
{
    int tmpValue = 3;
    int currentRow = 3;

    while (tmpValue > -1)
    {
        if (block[currentRow].back() == 0)
        {
            block[currentRow].pop_back();
        }            
        else
        {
            tmpValue = currentRow - 1;
        }           
        currentRow = ((currentRow - 1) + 4) % 4;
    }
    
    return block;
}

//make subWord using sbox
//input and output 16byte blocks
vector<vector<unsigned char>> &makeSubWord(vector<vector<unsigned char>> &block)
{
    for (int i = 0; i < 4; ++i)
    {
        for (int j = 0; j < 4; ++j)
        {
            auto row = get4FirstBit(block[i][j]);
            auto column = get4LastBit(block[i][j]);
            block[i][j] = sbox[row][column];
        }
    }

    return block;
}

//demake subWord using inverse sbox
//input and output 16byte blocks
vector<vector<unsigned char>> &deSubWord(vector<vector<unsigned char>> &block)
{
    for (int i = 0; i < 4; ++i)
    {
        for (int j = 0; j < 4; ++j)
        {
            auto row = get4FirstBit(block[i][j]);
            auto column = get4LastBit(block[i][j]);
            block[i][j] = inv_sbox[row][column];
        }
    }

    return block;
}

//make shift row for block
vector<vector<unsigned char>> &makeShiftRow(vector<vector<unsigned char>> &block)
{
    for (int i = 0; i < 4; ++i)
    {
        block[i] = cirShiftRow(block[i], shift_row_routine[i]);
    }
    
    return block;
}

//demake shift row for block
vector<vector<unsigned char>> &deShiftRow(vector<vector<unsigned char>> &block)
{
    for (int i = 0; i < 4; ++i)
    {
        block[i] = cirShiftRow(block[i], shift_row_routine[(4 - i) % 4]);
    }
    
    return block;
}

//make mix column for block
vector<vector<unsigned char>> makeMixColumn(vector<vector<unsigned char>> &block)
{
    vector<vector<unsigned char>> result(block.size());
    
    for (int i = 0; i < 4; ++i)
    {
        for (int j = 0; j < 4; ++j)
        {
            unsigned char tmp = 0;
            for (int k = 0; k < 4; ++k)
            {
                tmp ^= multipleGF2Bytes(const_mul_mat[i][k], block[k][j]);
            }
            result[i].push_back(tmp);
        }
        
    }

    return result;
}

//demake mix column for block
vector<vector<unsigned char>> deMixColumn(vector<vector<unsigned char>> &block)
{
    vector<vector<unsigned char>> result(block.size());
    
    for (int i = 0; i < 4; ++i)
    {
        for (int j = 0; j < 4; ++j)
        {
            unsigned char tmp = 0;
            for (int k = 0; k < 4; ++k)
            {
                tmp ^= multipleGF2Bytes(const_inv_mul_mat[i][k], block[k][j]);
            }
            result[i].push_back(tmp);
        }
        
    }

    return result;
}

//expand the key from 4word to 44word
vector<vector<unsigned char>> keyExpand(const vector<vector<unsigned char>> &key)
{
    vector<vector<unsigned char>> expandedKey(key);
    vector<vector<unsigned char>> tmpKey(4);
    for (int i = 4; i < 44; ++i)
    {
        for (int j = 0; j < 4; ++j)
        {
            tmpKey[j].push_back(expandedKey[j].back());
        }
            
        
        if(i % 4 == 0)
        {
            tmpKey = rotateWord(tmpKey);
            tmpKey = makeSubWord(tmpKey);
            
            for (int j = 0; j < 4; ++j)
            {
                tmpKey[j].back() ^= round_constants[j][(i / 4) - 1];
            }
        }

        for (int j = 0; j < 4; ++j)
        {
            expandedKey[j].push_back(expandedKey[j][i - 4] ^ tmpKey[j].back());
            tmpKey[j].clear();
        }
    }
    return expandedKey;    
}


//function encrypting the block AES with mode CBC
vector<vector<unsigned char>> encrypt(string plaintext, const vector<vector<unsigned char>> &key, const vector<vector<unsigned char>> &iv)
{
    vector<vector<unsigned char>> ciphertext(4);
    auto plaintextBlock = convertStringToBlock(plaintext);

    //add padding
    plaintextBlock = addPadding(plaintextBlock);

    //expand the key
    auto expandedKey = keyExpand(key);
    //set up CBC mode
    auto auxBlock = iv;

    //loop through the plaintext block
    for (int i = 0; i < plaintextBlock[0].size(); i += 4)
    {
        //split the plaintext block into 4 word
        auto currentPos = split(plaintextBlock, i);
        //set up CBC mode
        currentPos = xorTwoVector(currentPos, auxBlock);
        //split the expanded key into 4 word
        auto roundKeyZero = split(expandedKey, 0);

        //tnitial transformation
        currentPos = xorTwoVector(currentPos, roundKeyZero);

        //loop for 10 times
        for (int r = 1; r <= 10; ++r)
        {
            //make sub word
            currentPos = makeSubWord(currentPos);

            //make shift row
            currentPos = makeShiftRow(currentPos);

            //last round
            if (r < 10)
            {
                //make mix column
                currentPos = makeMixColumn(currentPos);
            }

            //add round key
            auto roundKey = split(expandedKey, r * 4);
            currentPos = xorTwoVector(currentPos, roundKey);
        }

        auxBlock = currentPos;

        //push back the currentPos to ciphertext
        for (int i = 0; i < 4; ++i)
        {
            for (int j = 0; j < 4; ++j)
            {
                ciphertext[i].push_back(currentPos[i][j]);
            }
        }
    }
    return ciphertext;
}

//function decrypting the block AES with mode CBC
string decrypt(const vector<vector<unsigned char>> &ciphertext, const vector<vector<unsigned char>> &key, const vector<vector<unsigned char>> &iv)
{
    vector<vector<unsigned char>> plaintextBlock(4);
    auto auxBlock = iv;

    //expand the key
    auto expandedkey = keyExpand(key);

    //loop through 4 words of the ciphertext at a time
    for (int i = 0; i < ciphertext[0].size(); i += 4)
    {
        //split the ciphertext into 4 words
        auto currentPos = split(ciphertext, i);

        //set up CBC mode
        auto secondAuxBlock = currentPos;

        //split the expanded key into 10 words
        auto roundKeyTen = split(expandedkey, 40);

        //initial transformation
        currentPos = xorTwoVector(currentPos, roundKeyTen);

        //loop for 10 times
        for (int r = 9; r >= 0; --r)
        {
            //deshift row
            currentPos = deShiftRow(currentPos);

            //dessub word
            currentPos = deSubWord(currentPos);

            //split the expanded key and add round key
            auto roundKey = split(expandedkey, r * 4);
            currentPos = xorTwoVector(currentPos, roundKey);

            if (r > 0)
            {
                //demix column
                currentPos = deMixColumn(currentPos);
            }
        }

        //CBC mode
        currentPos = xorTwoVector(currentPos, auxBlock);
        auxBlock = secondAuxBlock;

        //push back the current state to the plaintext
        for (int i = 0; i < 4; ++i)
        {
            for (int j = 0; j < 4; ++j)
            {
                plaintextBlock[i].push_back(currentPos[i][j]);
            }
        }
    }
    plaintextBlock = removePadding(plaintextBlock);
    return convertBlockToString(plaintextBlock);
}

//get data from console using 2 direction vector
vector<vector<unsigned char>> getDataFromConsole(wstring type)
{
    wstring winputData;
    string inputData;
    wcout << L"Nhập " + type + L": ";

    wcin >> winputData;

    inputData = ws2s(winputData);

    auto data = convertStringToBlock(inputData);

    if (data.size() >= 64)
    {
        return split(data, 0);
    }
    else
    {
        data = addPadding(data);
        return data;
    }
}

//check input data is correct or not
bool checkInput(vector<vector<unsigned char>> &data, wstring type)
{
    try
    {
        data = getDataFromConsole(type);
        return true;
    }
    catch(const std::exception& e)
    {
        wcout << e.what() << '\n';
        fflush(stdin);
        return false;
    }
    
}

int main(int argc, char** argv[]) 
{
    setUpVietnamese();
    
    //declare variables
    string plaintext;
    wstring wplaintext;
    
    
    //get plaintext
    std::wcout << L"Nhập vào chuỗi cần mã hóa: ";
    getline(wcin, wplaintext);
    plaintext = ws2s(wplaintext);

    //get and check the key    
    vector<vector<unsigned char>> key(4);
    if(!checkInput(key, L"key"))
    {
        wcout << L"Lỗi input key" << endl;
        return 0;
    }

    //get and check the iv    
    vector<vector<unsigned char>> iv;
    if(!checkInput(iv, L"iv"))
    {
        wcout << L"Lỗi input iv" << endl;
        return 0;
    }
    
    //show result
    
    //show plaintext
    wcout << L"Plaintext: " << wplaintext << endl;

    //show key
    wcout << L"Key: ";
    printHexString(key);

    //show iv
    wcout << L"IV: ";
    printHexString(iv);

    //encrypt and show ciphertext
    auto ciphertext = encrypt(plaintext, key, iv);
    wcout << L"Ciphertext: ";
    printHexString(ciphertext);

    //decrypt and show plaintext
    string recovertext = decrypt(ciphertext, key, iv);
    wstring wrecovertext = s2ws(recovertext);
    wcout << L"Recovertext: " << wrecovertext << endl;
    
    return 0;
}