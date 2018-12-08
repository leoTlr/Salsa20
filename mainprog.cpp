#include <iostream>
#include <fstream>
#include <string>
#include <vector>

#include "salsa20.hpp"

using namespace std;

void usage(string progname) {
    cout << "usage:\n"
         << progname << " infile outfile key nonce \n"
         << "32 byte key as str, 8 byte nonce in hex (without 0x prefix)" << endl;
    exit(EXIT_FAILURE);
}

int main(int argc, char** argv){

    if (argc != 5) usage(argv[0]);

    string infile_str=argv[1], outfile_str=argv[2], key_hex_str=argv[3], nonce_hex_str=argv[4];

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
    if (key_hex_str.length() != 32) {
        cerr << "Invalid key length. Has to be 32 chars" << endl;
        exit(EXIT_FAILURE);
    }

    //Salsa20 s = Salsa20(key_hex_str);
    //s.setNonce(nonce_hex_str);
    vector<uint8_t> key(32); // debug
    //key[3] = (uint8_t) 0x80;
    cout << hex << "k0 :" << (unsigned) key[0] << endl;
    uint64_t iv = 0; // debug
    //string key = "8000000000000000000000000000000000000000000000000000000000000000";
    //string iv = "0000000000000000";
    string ctr = "0000000000000000";

    Salsa20 s = Salsa20(key); cout << "constr done" << endl;
    s.setNonce(iv); cout << "nonce set"<< endl;
    //s.setCounter(ctr); cout << "ctr set" << endl;
    s.dbgPrintMatrix("all set, b4 encr");

    s.tests();
    //uint8_t byte[64] = {0};
    uint8_t encrypted_bytes[64] = {0};

    for (int bl=0; bl<4; bl++){
        s.keyStreamBlock(&encrypted_bytes[0]);
        cout << "---block " << dec << bl << " stream "  << 64*bl << " to " << (64*(bl+1))-1;
        for (int i=0; i<64; i++) {
            if (i%16==0) cout << "\n";
            cout << hex << (unsigned) encrypted_bytes[i] << " ";
        }
        cout << "\n" <<endl;
    }

    /*
    while (infile.good() && !infile.eof() && outfile.good()) {

        infile.read((char*)&byte, sizeof(byte)*64);

        s.encryptBytes(&byte[0], &encrypted_bytes[0], 64);

        outfile.write((char*)&encrypted_bytes, sizeof(byte)*64);
    }*/

    infile.close();
    outfile.close();
    return 0;
}