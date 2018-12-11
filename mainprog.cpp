#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <stdexcept>
#include <cstring> // memset

#include "salsa20.hpp"

using namespace std;

/*  Small program to show sample usage of this Salsa20 cipher implementation

    Encrypt infile with Salsa20 into outfile in 64byte blocks
*/

void usage(string progname) {
    cout << "usage:\n"
         << progname << " infile outfile key nonce [--hex-key]\n"
         << "32 byte key as (ascii interpreted) str, 8 byte nonce in hex (without 0x prefix)" << endl;
    exit(EXIT_FAILURE);
}

int main(int argc, char** argv){

    // -------------- input validation --------------------
    if (argc < 5) usage(argv[0]);

    string infile_str=argv[1], outfile_str=argv[2], key_str=argv[3], nonce_hex_str=argv[4];
    string hex_key_arg = "";
    bool hex_key = false;
    if (argc == 6) {
        hex_key_arg += string(argv[5]);
        if (hex_key_arg == "--hex-key")
            hex_key = true;
        else {
            cerr << "unknown arguemnt " << hex_key_arg << endl;
            exit(EXIT_FAILURE); 
        }
    }

    ifstream infile(infile_str, ios::in | ios::binary);
    if (!infile) {
        cerr << "Could not open " << infile_str << endl;
        exit(EXIT_FAILURE);
    }
    ofstream outfile(outfile_str, ios::out | ios::binary);
    if (!outfile) {
        cerr << "Could not open " << outfile_str << endl;
        exit(EXIT_FAILURE); 
    }

    Salsa20* s_ptr = nullptr;
    try {
        if (hex_key) {
            Salsa20 s20obj = Salsa20(key_str, true);
            s_ptr = &s20obj;
        } else {
            Salsa20 s20obj = Salsa20(key_str, false);
            s_ptr = &s20obj;
        }
    } catch (length_error&) {
        if (!hex_key)
            cerr << "invalid key size. has to be 16 or 32 (ascii interpreted) chars" << endl;
        else
            cerr << "invalid key size. has to be 32 or 64 hex chars" << endl;
    } catch (invalid_argument&) {
        cerr << "all key chars have to be hex chars (no 0x prefix)" << endl;
    }

    if (!s_ptr) exit(EXIT_FAILURE);
    Salsa20 s20 = *s_ptr;

    try {
        s20.setNonce(nonce_hex_str);
    } catch (length_error&) {
        cerr << "invalid nonce size. has to be 8 byte (16 hex interpreted chars) without 0x prefix)" << endl;
        exit(EXIT_FAILURE);
    } catch (invalid_argument&) {
        cerr << "nonce hast to consist of only hex chars (also no 0x prefix)" << endl;
        exit(EXIT_FAILURE);        
    }

    // -------------- end of input validation -------------

    uint8_t inblock[64];
    uint8_t outblock[64];

    // encrypt infile into outfile in 64 by te chunks
    while (infile.good() && !infile.eof() && outfile.good()) {
        memset(inblock, 0, sizeof(inblock));
        memset(outblock, 0, sizeof(outblock));

        infile.read((char*)&inblock, sizeof(inblock));

        s20.encryptBytes(inblock, outblock, sizeof(inblock));

        outfile.write((char*)outblock, sizeof(outblock));
    }

    infile.close();
    outfile.close();
    return 0;
}