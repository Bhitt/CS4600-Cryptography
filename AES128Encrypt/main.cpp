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
#include <string>
#include <windows.h>

using namespace std;

//User libraries

//Global Constants

//Function Prototypes
string maskedInput();

//Execution begins here
int main(int argc, char** argv) {
    // filepath passed in on the command line
    string src_filepath = argv[1];
        //cout<<"src_filepath:"<<src_filepath<<endl;
    // destination is filepath as the source with a ".enc" filename extension
    string dst_filepath = src_filepath.replace(src_filepath.find(".txt"),4,".enc");
        //cout<<"src_filepath: "<<src_filepath;
    /* 32 digit hex value to be taken from the user as hex digits (4 bits each) 
       with nothing echoed in the terminal */
    string key = maskedInput();
    //the above code needs to only accept 32 bit keys
    cout<<"key:"<<key<<endl;
    
    return 0;
}

string maskedInput(){
    const char BACKSPACE=8;
    const char RETURN=13;

    string password;
    unsigned char ch=0;

    cout<<"Enter in your 32 digit hex value key now:"<<endl;

    DWORD con_mode;
    DWORD dwRead;

    HANDLE hIn=GetStdHandle(STD_INPUT_HANDLE);

    GetConsoleMode( hIn, &con_mode );
    SetConsoleMode( hIn, con_mode & ~(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT) );

    while(ReadConsoleA( hIn, &ch, 1, &dwRead, NULL) && ch !=RETURN)
      {
         if(ch==BACKSPACE)
           {
              if(password.length()!=0)
                {
                   password.resize(password.length()-1);
                }
           }
         else
           {
               password+=ch;
           }
      }
    return password;
}

////Method for encryption
//void AES128Encrypt(){

//key_schedule[11] = get_key_schedule(key) // precalc all round-keys
//src_file_descriptor = open_file(src_filepath, read) //open the plaintext file
//dst_file_descriptor = open_file(dst_filepath, write) //open the new ciphertext
//buffer[16] f_buffer // a buffer of 16 bytes
//while src_file_descriptor != EOF do
    //bytes_read = read_file(src_file_descriptor, f_buffer)
    //// need 16 bytes of plaintext for each round.
    //if bytes_read < 16 then pad_with_zero(f_buffer, bytes_read)
    //key_add(key_schedule[0], f_buffer()) // pre-round key addition
    //for i = 1 to 9 do
        //sub_bytes(f_buffer) // byte-substitution layer (use sbox map)
        //shift_rows(f_buffer) // shiftrow layer
        //mix_columns(f_buffer) // shiftcol layer
        //key_add(key_schedule[i], f_buffer()) // round-key addition
    //next
    //sub_bytes(f_buffer)
    //shift_rows(f_buffer)
    //key_add(key_schedule[10], f_buffer())
    //// write 16 bytes of buffer to ciphertext file
    //read_file(dst_file_descriptor, f_buffer, 16)
//loop
//close_file(src_file_descriptor)
//close_file(dst_file_descriptor)
//}



