/*
 * Author: Branden Hitt
 * Purpose: Take plaintext and encrypt using AES 128 encryption
 */

/* 
 * File:   main.cpp
 * Author: bhitt
 *
 * Created on October 8, 2019, 2:43 PM
 */

//System Libraries
#include <iostream>
#include <bitset>
#include <string>
#include <cstring>
#include <fstream>

using namespace std;

//Enums
typedef bitset<32> word;
typedef bitset<8> byte;
typedef bitset<128> dataBlock;

//User libraries

//Global Constants
bool flag = true;

unsigned char sbox[256] = { //s-box
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

//unsigned char rcon[11] = {0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36}; //round constants
word Rcon[10] = {0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,   
                 0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000};

//Function Prototypes
//****conversions***//
byte toByte(unsigned char b);
void charToByte(byte out[16], const char s[16]);
void divideToByte(byte out[16], dataBlock& data);
void swapByteOrder(byte p[16]);
dataBlock mergeByte(byte in[16]);
//****key expansions***//
word toWord(byte& k1, byte& k2, byte& k3, byte& k4);
word rotateWord(word w);
word subWord(word w);
void keyExpansion(byte key[16], word keySchedule[44]);
//****encryption****//
void encrypt(byte in[16], word w[44]);
void AddRoundKey(byte mtx[16], word k[4]);
void SubBytes(byte mtx[16]);
void ShiftRows(byte mtx[16]);
void MixColumns(byte mtx[16]);
byte GFMul(byte a, byte b);

//Execution begins here
int main(int argc, char** argv) {
    //variable declaration for the key
    string keyString = "F52B67EA34012298EF984755ABCC25A1";
    byte key[16];
    // filepath passed in on the command line
    string src_filepath = argv[1];
    // destination is filepath as the source with a ".enc" filename extension
    string dst_filepath = src_filepath.replace(src_filepath.find(".txt"),4,".enc");
    /* 32 digit hex value to be taken from the user as hex digits (4 bits each) 
       with nothing echoed in the terminal */
    //the above code needs to only accept 32 bit keys
    //remember to ignore whitespaces
    
    //send the string of chars to be converted to bytes
    string tempPath1 = "m.pdf";
    string tempPath2 = "m.enc";
    
    //convert the key string to a byte array
    charToByte(key, keyString.c_str());
    
    //create the key schedule
    word keySchedule[44];
    keyExpansion(key,keySchedule);
    for(int i=0;i<11;i++){
        cout<<"Round"<<i<<':'<<keySchedule[i]<<' '<<keySchedule[i+1]<<' '<<keySchedule[i+2]<<' '<<keySchedule[i+3]<<endl;
    }
    
    //fetch the data from the file
    dataBlock data; // 128 bits at a time
    byte plain[16]; // bits are stored in byte array
    
    ifstream in;
    ofstream out;
    in.open(tempPath1, ios::binary);  //open the file specified
    out.open(tempPath2, ios::binary);  //output to file specified
    while(in.read((char*)&data, sizeof(data)))  
    {  
        divideToByte(plain, data);
        swapByteOrder(plain);
        if(flag){
            cout<<"plain[0] :"<<plain[0]<<endl;
            cout<<"plain[15]:"<<plain[15]<<endl;
            flag=false;
        }
        

        encrypt(plain, keySchedule);  
        data = mergeByte(plain);
        out.write((char*)&data, sizeof(data));  
        data.reset();  //Set 0  
    } 
    in.close();  
    out.close();  
    
//    byte plain[16] = {0x25,0x50,0x44,0x46,0x2d,0x31,0x2e,0x35,0x0a,0x25,0xbf,0xf7,0xa2,0xfe,0x0a,0x32};
//    cout<<endl;
//        cout<<plain[0]<<endl;
//    encrypt(plain, keySchedule);
//    cout<<endl;
//        cout<<plain[0]<<endl;
    
    
    
    return 0;
}
/*
     ************* Conversions ******************   
 */

//convert to byte
byte toByte(unsigned char b){
    return byte(b);
}

//convert char array to byte array
void charToByte(byte out[16], const char s[16]){
    for(int i=0; i<16; ++i){
        for(int j=0;j<8; ++j){
            out[i][j]=((s[i]>>j)&1);
        }
    }
}

//swap order of bytes because of endianess
void swapByteOrder(byte p[16]){
    byte temp[16];
    for(int i=0;i<16;i++){
        temp[i] = p[15-i]; 
    }
    if(flag) cout<<"before p[0]"<<p[0]<<endl;
    
    for(int i=0;i<16;i++){
        p[i] = temp[i];
    }
    
    if (flag) cout<<"p[0]"<<p[0]<<endl;
}

// take 128 bits and send them into 16 bytes in an array of bytes 
void divideToByte(byte out[16], dataBlock& data){  
    dataBlock temp;  
    for(int i=0; i<16; ++i){  
        temp = (data << 8*i) >> 120;  
        out[i] = temp.to_ulong();  
    }
}
  
// take 16 bytes and send them into 128 bits  
dataBlock mergeByte(byte in[16]){  
    dataBlock res;  
    res.reset();  //Set 0  
    dataBlock temp;  
    for(int i=0; i<16; ++i){  
        temp = in[i].to_ulong();  
        temp <<= 8*(15-i);  
        res |= temp;  
    }  
    return res;  
} 

/*
     ************* KEY EXPANSION ******************   
 */

//convert four bytes to one word
word toWord(byte& k1, byte& k2, byte& k3, byte& k4){
    word result=(0x00000000);  
    word temp;  
    temp = k1.to_ulong();  // K1  
    temp <<= 24;  
    result |= temp;  
    temp = k2.to_ulong();  // K2  
    temp <<= 16;  
    result |= temp;  
    temp = k3.to_ulong();  // K3  
    temp <<= 8;  
    result |= temp;  
    temp = k4.to_ulong();  // K4  
    result |= temp;  
    return result;
}

/*rotate word -> left shift cyclic 
 * ex: [b0,b1,b2,b3] rotates to [b1,b2,b3,b0] */
word rotateWord(word w){
    word high = w << 8;  
    word low = w >> 24;  
    return high | low;  
}

// S-box byte substitution on single word
word subWord(word w){
    //create temporary word
    word temp;
    //substitute all four bytes
    for(int i=0;i<32;i+=8){
        int row = w[i+7]*8 +  w[i+6]*4 + w[i+5]*2 + w[i+4];  
        int col = w[i+3]*8 + w[i+2]*4 + w[i+1]*2 + w[i];  
        byte val = toByte( sbox[(row*16)+col] );  
        for(int j=0; j<8; ++j)  
            temp[i+j] = val[j];  
    }  
    return temp;
}

// use 128 bit key to create keyschedule
void keyExpansion(byte key[16], word keySchedule[44]){
    //create a temporary word
    word temp;
    int i=0; //index
    //first four words of keySchedule are input key words
    while(i < 4){
        keySchedule[i] = toWord(key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]);
        ++i;
    }
    //set i to 4
    i=4;
    while(i < 44){  // 44 total words in key schedule (4 per 11 rounds)
        temp = keySchedule[i-1]; // keep the previous word
//        if(i%4 == 0){ //core function
//            word temp2 = rotateWord(temp);  //left shift cyclic the bytes in the word
//            temp2 = subWord(temp2);         //s-box the bytes in the word
//            temp2 = temp2 ^ Rcon[(i/4)-1];  //xor the first byte with the round constant
//            keySchedule[i] = keySchedule[i-4]^ temp2;
//            cout<<"keySch["<<i<<"]:"<<keySchedule[i]<<endl;
//        }else{   //just xor
//            keySchedule[i] = keySchedule[i-4]^temp;
//        }
        if( i%4 == 0 ){ //core function
            temp = subWord(rotateWord(temp)) ^ Rcon[i/4-1];
        }
        keySchedule[i] = keySchedule[i-4]^temp;
        ++i;
    }
}

/*
     ************* Encryption ******************   
 */
void encrypt(byte in[16], word w[44]){
    word key[4]; //current round key 
    for(int i=0; i<4; ++i)
        key[i] = w[i];  
    AddRoundKey(in, key); //start by adding the round key to the plain text
    //first 9 rounds
    for(int round=1; round<10; ++round)  
    {  
        SubBytes(in);   //byte substitution layer
        ShiftRows(in);  //shift rows layer
        MixColumns(in); //mix columns layer 
        for(int i=0; i<4; ++i)  //get the next round key
            key[i] = w[4*round+i];  
        AddRoundKey(in, key);  //key addition layer
    }  
    //final round
    SubBytes(in);  
    ShiftRows(in);  
    for(int i=0; i<4; ++i)  
        key[i] = w[40+i];  
    AddRoundKey(in, key);  
}

// Key addition layer
void AddRoundKey(byte mtx[16], word k[4]){  
    for(int i=0; i<4; ++i)  
    {  
        word k1 = k[i] >> 24;  
        word k2 = (k[i] << 8) >> 24;  
        word k3 = (k[i] << 16) >> 24;  
        word k4 = (k[i] << 24) >> 24;  
          
        mtx[i] = mtx[i] ^ byte(k1.to_ulong());  
        mtx[i+4] = mtx[i+4] ^ byte(k2.to_ulong());  
        mtx[i+8] = mtx[i+8] ^ byte(k3.to_ulong());  
        mtx[i+12] = mtx[i+12] ^ byte(k4.to_ulong());  
    } 
}  

// Byte Substitution layer
void SubBytes(byte mtx[16]){  
    for(int i=0; i<16; ++i)  
    {  
        int row = mtx[i][7]*8 + mtx[i][6]*4 + mtx[i][5]*2 + mtx[i][4];  
        int col = mtx[i][3]*8 + mtx[i][2]*4 + mtx[i][1]*2 + mtx[i][0];  
        mtx[i] = toByte( sbox[(row*16)+col] );   
    }  
}  

// Shift row layer 
void ShiftRows(byte mtx[16]){  
    //The second row of matrix shifts left once
    byte temp = mtx[4];
    for(int i=0; i<3; ++i)  
        mtx[i+4] = mtx[i+5];  
    mtx[7] = temp;  
    //The third row of matrix shifts left twice
    for(int i=0; i<2; ++i)  
    {  
        temp = mtx[i+8];  
        mtx[i+8] = mtx[i+10];  
        mtx[i+10] = temp;  
    }  
    //The fourth row of matrix shifts left three times
    temp = mtx[15];  
    for(int i=3; i>0; --i)  
        mtx[i+12] = mtx[i+11];  
    mtx[12] = temp;
}

// Mix Columns Layer
void MixColumns(byte mtx[16]){  
    byte arr[4];  
    for(int i=0; i<4; ++i){  
        for(int j=0; j<4; ++j)  
            arr[j] = mtx[i+j*4];  
        mtx[i] = GFMul(0x02, arr[0]) ^ GFMul(0x03, arr[1]) ^ arr[2] ^ arr[3];  
        mtx[i+4] = arr[0] ^ GFMul(0x02, arr[1]) ^ GFMul(0x03, arr[2]) ^ arr[3];  
        mtx[i+8] = arr[0] ^ arr[1] ^ GFMul(0x02, arr[2]) ^ GFMul(0x03, arr[3]);  
        mtx[i+12] = GFMul(0x03, arr[0]) ^ arr[1] ^ arr[2] ^ GFMul(0x02, arr[3]);  
    }
}

// Multiplication over GF (2^8)
byte GFMul(byte a, byte b){   
    byte p = 0;  
    byte hi_bit_set;  
    for (int counter = 0; counter < 8; counter++){  
        if ((b & byte(1)) != 0){  
            p ^= a;  
        }  
        hi_bit_set = (byte) (a & byte(0x80));  
        a <<= 1;  
        if (hi_bit_set != 0){  
            a ^= 0x1b; /* x^8 + x^4 + x^3 + x + 1 */  
        }  
        b >>= 1;  
    }  
    return p;  
}  