#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <stdexcept>

#include "salsa20.hpp"

#define NR_POS_ARGS 4
#define NR_OPT_ARGS 2
#define MIN_ARGC (NR_POS_ARGS+1)
#define MAX_ARGC (NR_POS_ARGS+NR_OPT_ARGS+1)

using namespace std;

/*  Small program to show sample usage of this Salsa20 cipher implementation

    Encrypt infile with Salsa20 into outfile (or with Chacha20 if --chacha20 set)
*/

void usage(string progname) {
    cout << "usage:\n"
         << progname << " infile outfile key nonce [--hex-key] [--chacha20]\n"
         << "32 byte key as (ascii interpreted) str, 8 byte nonce in hex (without 0x prefix)" << endl;
    exit(EXIT_FAILURE);
}

int main(int argc, char** argv){

    // -------------- input validation --------------------
    if (argc < MIN_ARGC || argc > MAX_ARGC)
        usage(argv[0]);

    string infile_str=argv[1], outfile_str=argv[2], key_str=argv[3], nonce_hex_str=argv[4];
    string optional_arg;
    bool is_hex_key = false;
    bool use_chacha = false;

    if (argc > MIN_ARGC) {
        for (int i=MIN_ARGC; i<argc; i++) {
            optional_arg = string(argv[i]);
            if (optional_arg == "--hex-key")
                is_hex_key = true;
            else if (optional_arg == "--chacha20")
                use_chacha = true;
            else {
                cerr << "unknown arguemnt: " << optional_arg << endl;
                exit(EXIT_FAILURE); 
            }
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

    SnuffleStreamCipher* cipher_ptr;
    try {
        if (use_chacha) 
            cipher_ptr = new Chacha20(key_str, is_hex_key);
        else 
            cipher_ptr = new Salsa20(key_str, is_hex_key);
    } catch (length_error&) {
        if (!is_hex_key)
            cerr << "invalid key size. has to be 16 or 32 (ascii interpreted) chars" << endl;
        else
            cerr << "invalid key size. has to be 32 or 64 hex chars" << endl;
    } catch (invalid_argument&) {
        cerr << "all key chars have to be hex chars (no 0x prefix)" << endl;
    }

    if (!cipher_ptr)
        exit(EXIT_FAILURE);    

    try {
        cipher_ptr->setNonce(nonce_hex_str);
    } catch (length_error&) {
        cerr << "invalid nonce size. has to be 8 byte (16 hex interpreted chars) without 0x prefix)" << endl;
        exit(EXIT_FAILURE);
    } catch (invalid_argument&) {
        cerr << "nonce hast to consist of only hex chars (also no 0x prefix)" << endl;
        exit(EXIT_FAILURE);        
    }

    // -------------- end of input validation -------------

    int filesize;

    // get filesize
    infile.seekg(0, infile.end);
    filesize = infile.tellg();
    infile.seekg(0, infile.beg);
    if (filesize < 0) {
        cerr << "Error getting filesize" << endl;
        exit(EXIT_FAILURE);
    } 

    vector<uint8_t> input (filesize);

    // encrypt input bytevector in place
    if (!infile.good()) {
        cerr << "Error reading infile" << endl;
        exit(EXIT_FAILURE);            
    } else if (!outfile.good()) {
        cerr << "Error writing outfile" << endl;
        exit(EXIT_FAILURE);            
    } else {
        infile.read((char *) input.data(), filesize);
        cipher_ptr->encryptBytes(input);
        outfile.write((char *) input.data(), filesize);
    }

    infile.close();
    outfile.close();
    delete cipher_ptr;
    return 0;
}