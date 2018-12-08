#include <cstring> // memset
#include <cassert>
#include <algorithm> // std::all_of()
#include <sstream> // hex str to ulong conversion
#include <iomanip> // std::hex
#include <stdlib.h> // strtoul()
#include <limits.h> // Salsa20::incrementCounter()
#include <stdint.h> // uintX_t types
#include <stdexcept> //std::length_error

#include "salsa20.hpp"

using namespace std;

/*  Constructor for key as string.
    If hex_key is set, iterpreted as hex chars, else ascii
    Only 16 or 32 byte keys allowed, else an Exception is thrown    */ 
Salsa20::Salsa20(const string key_str, bool hex_key) {
    uint32_t key[8];

    switch (hex_key) {

    case false: // interpret as ascii

        if (!(key_str.size()==16 || key_str.size()==32))
            throw length_error("Keylength has to be 16 or 32 byte"); 

        // 4 keystr chars -> one 32bit word
        for (uint8_t i=0, j=0; i<key_str.length(); i+=4, j++)
            key[j] = charsToLittleEndianWord(key_str, i);

        // if short key, copy same key in other half of key blocks
        if (key_str.length() == 32) { 
            memcpy(&key[4], &key[0], sizeof(key[0])*4);
            initMatrix(key, 16);
        } else
            initMatrix(key, 32);

        break;

    case true: // interpret as hex string

        if (!(key_str.size()==32 || key_str.size()==64)) {
            throw length_error("Keylength has to be 16 or 32 byte (32 or 64 hex chars, no 0x prefix)"); 
        }

        // 8 keystr hex chars -> one 32bit word
        for (uint8_t i=0, j=0; i<key_str.length(); i+=8, j++)
            key[j] = hexCharsToLittleEndianWord(key_str, i);

        // if short key, copy same key in other half of key blocks
        if (key_str.length() == 32) { 
            memcpy(&key[4], &key[0], sizeof(key[0])*4);
            initMatrix(key, 16);
        } else
            initMatrix(key, 32);
    }    
}

/*  Constructor for key as bytevector
    Takes a std::vector<uint8_t> with bytes used as key
    Only 16 or 32 byte keys allowed, else an Exception is thrown    */ 
Salsa20::Salsa20(const vector<uint8_t> key) {
    if (!(key.size()==16 || key.size()==32))
        throw length_error("Keylength has to be 16 or 32 byte");

    uint32_t key_words[8];

    for (uint8_t i=0, j=0; (i < (key.size() / 4) && j < key.size()); i++, j+=4) {
        key_words[i] = littleEndianWordFromBytes(&key[j]);
        //cout << "kwrds " << i << " "<<(unsigned) key_words[i] << " "<< (unsigned) key[j] << endl;
    }

    // if keysize 16 byte duplicate into the remaining 16 byte
    if (key.size() == 16) {
        memcpy(&key_words[4], &key_words[0], 4*sizeof(key_words));
        initMatrix(key_words, 16);
    } else
        initMatrix(key_words, 32);
};

// create a 32bit little endian word from four bytes
uint32_t Salsa20::littleEndianWordFromBytes(const uint8_t* bytes) {
    return  bytes[0] + \
            ((uint_fast16_t) bytes[1] <<  8) + \
            ((uint_fast32_t) bytes[2] << 16) + \
            ((uint_fast32_t) bytes[3] << 24);
};

// puts a 32bit word into the four bytes pointed to
void Salsa20::bytesFromLittleEndianWord(const uint32_t word, uint8_t* bytes) {
    bytes[0] = word;
    bytes[1] = word >> 8;
    bytes[2] = word >> 16;
    bytes[3] = word >> 24;
};

void Salsa20::initMatrix(const uint32_t key[8], const size_t keylen) {
    assert(sizeof(&key) == 8);
    assert(keylen == 16 || keylen == 32);    

    /*  init matrix using uint32_t key[8]
        constants depend on keylength

        Nonce and Counter 0 by default
        use setNonce() and setCounter()
    */

    static const char constants_32byte_key[17] = "expand 32-byte k";
    static const char constants_16byte_key[17] = "expand 16-byte k";

    const char* constants;

    if (keylen == 32)
        constants = constants_32byte_key;
    else if (keylen == 16)
        constants = constants_16byte_key;

    _matrix[0][0] = littleEndianWordFromBytes((const uint8_t *) constants);
    _matrix[0][1] = key[0];
    _matrix[0][2] = key[1];
    _matrix[0][3] = key[2];

    _matrix[1][0] = key[3];
    _matrix[1][1] = littleEndianWordFromBytes((const uint8_t *) (constants+4));
    // 2 * nonce

    // 2 * counter
    _matrix[2][2] = littleEndianWordFromBytes((const uint8_t *) (constants+8)); 
    _matrix[2][3] = key[4];

    _matrix[3][0] = key[5];
    _matrix[3][1] = key[6];
    _matrix[3][2] = key[7];
    _matrix[3][3] = littleEndianWordFromBytes((const uint8_t *) (constants+12));
}

// set nonce to nonce and counter to 0 as nonce is used as IV
void Salsa20::setNonce(const uint64_t nonce) {
    
    _matrix[1][2] = (uint32_t) ((nonce & 0xffffffff00000000) >> 32);
    _matrix[1][3] = (uint32_t) ((nonce & 0x00000000ffffffff) >> 32);
    setCounter(0);
}

// nonce/IV interpreted as hex chars
// set nonce to (uint32_t) hex_str and counter to 0 as nonce is used as IV
void Salsa20::setNonce(const string hex_str) {
    assert(hex_str.length() == 16);

    _matrix[1][2] = hexCharsToLittleEndianWord(hex_str, 0);
    _matrix[1][3] = hexCharsToLittleEndianWord(hex_str, 8);
    setCounter(0);
}

void Salsa20::setCounter(const uint64_t counter) {

    _matrix[2][0] = (uint32_t) ((counter & 0xffffffff00000000) >> 32);
    _matrix[2][1] = (uint32_t) ((counter & 0x00000000ffffffff) >> 32);
}

// set counter/IV from hex string
void Salsa20::setCounter(const string hex_str) {
    assert(hex_str.length() == 16);

    _matrix[2][0] = hexCharsToLittleEndianWord(hex_str, 0);
    _matrix[2][1] = hexCharsToLittleEndianWord(hex_str, 8);
}

void Salsa20::incrementCounter() {
    // try to increment counter, exit if too large
    // counter is 2*uint32 at _matrix[1][2] and _matrix[1][3] 

    if (_matrix[1][3] == UINT32_MAX) {
        if (_matrix[1][2] == UINT32_MAX) {
            cerr << "ERROR: Counter too large" << endl;
            exit(EXIT_FAILURE);
        }
        _matrix[1][2]++;
    } else _matrix[1][3]++;
}

// quarter-round on each row
void Salsa20::rowRound(uint32_t state[4][4]) {
    quarterRound(state[0][0], state[0][1], state[0][2], state[0][3]);
    quarterRound(state[1][1], state[1][2], state[1][3], state[1][0]);
    quarterRound(state[2][2], state[2][3], state[2][0], state[2][1]);
    quarterRound(state[3][3], state[3][0], state[3][1], state[3][2]);
}

// quarter-round on each column
void Salsa20::columnRound(uint32_t state[4][4]) {
    quarterRound(state[0][0], state[1][0], state[2][0], state[3][0]);
    quarterRound(state[1][1], state[2][1], state[3][1], state[0][1]);
    quarterRound(state[2][2], state[3][2], state[0][2], state[1][2]);
    quarterRound(state[3][3], state[0][3], state[1][3], state[2][3]);
}

// first column, then row-round
void Salsa20::doubleRound(uint32_t state[4][4]) {
    columnRound(state);
    rowRound(state);
}

// left rotation by bits bit
uint32_t Salsa20::rotate(const uint32_t val, const uint8_t bits) {
    return (val << bits) | (val >> (32 - bits));
}

void Salsa20::quarterRound(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
    b ^= rotate((a+d), 7);
    c ^= rotate((b+a), 9);
    d ^= rotate((c+b), 13);
    a ^= rotate((d+c), 18);
}

// generate one block (64byte) of keystream
void Salsa20::keyStreamBlock(uint8_t* out_block) {

    // make copy of matrix as we need the original matrix later 
    uint32_t state[4][4];
    memcpy(&state, &_matrix, sizeof(_matrix)); cout << 4*4*sizeof(uint32_t) << endl;
    
    // 10 double-rounds -> 20 rounds
    for (uint8_t i=0; i<20; i+=2)
        doubleRound(state);

    // add original state to processed state (normal addition mod 2**32)
    for (uint8_t row=0; row<4; row++) 
        for (uint8_t col=0; col<4; col++)
            state[row][col] += _matrix[row][col];

    // split state into bytes and fill out_block
    //int i=0;
    for (uint8_t row=0, i=0; row<4; row++) {
        for (uint8_t col=0; col<4; col++) {
            cout << hex << (unsigned)state[row][col] << " ";
            bytesFromLittleEndianWord(state[row][col], out_block+i);
            i+=4;
        } cout << endl;
    }

    state[1][2]++;
    cout << "ctr : " << !state[1][2] << " " << (unsigned)state[1][2] <<" " << (unsigned)state[1][3]<< endl;
    if (!state[1][2])
        state[1][3]++;

    // increment counter
    //uint64_t ctr = (( (uint64_t) _matrix[1][2] << 32) + _matrix[1][3]);
    //incrementCounter();
}

void Salsa20::encryptBytes(uint8_t* input, uint8_t* output, const size_t num_bytes) {
    assert(input != nullptr && output != nullptr);
    if (num_bytes==0) return;

    // allocate once and reuse it
    static uint8_t block[64] ={0};
    
    for (size_t i=0; i<num_bytes; i++) {

        // get new block of keystream after every 64 bytes
        _stream_pos %= 64;
        if (_stream_pos == 0) 
            keyStreamBlock(block);
        
        // xor input byte with keystream byte incrementing pointers
        *(output++) = block[_stream_pos++] ^ *(input++);
    }
}

// interpret string as hex and put values in littleEndianWordFromBytes()
uint32_t Salsa20::hexCharsToLittleEndianWord(const string hex_str, size_t start_pos) {
    assert(all_of(hex_str.begin(), hex_str.end(), ::isxdigit));
    assert(start_pos+8 <= hex_str.length());

    uint8_t bytes[4];
    for (uint8_t i=0; i<4; i++)
        bytes[i] = stoul(hex_str.substr((start_pos+(2*i)), 2), nullptr, 16);   

    return littleEndianWordFromBytes(bytes);
}

// take the numerical values of four chars and put them into littleEndianWordFomBytes()
uint32_t Salsa20::charsToLittleEndianWord(const string str, size_t start_pos) {
    assert((start_pos+4) <= str.length());

    return littleEndianWordFromBytes((const uint8_t *) (&(str.c_str()[start_pos])));
}

/*  test-cases for every part of encryption process
    (values from http://cr.yp.to/snuffle/spec.pdf)  
    
    assertions on output of each test-case
*/
void Salsa20::tests(){

    // bytes to word conversion functions
    uint8_t le_testbytes[4] = {86, 75, 30, 9};
    uint32_t tstwrd = littleEndianWordFromBytes(le_testbytes);
    assert(tstwrd == (uint32_t) 0x091e4b56);
    uint8_t le_testbytes_2[4];
    bytesFromLittleEndianWord(tstwrd, le_testbytes_2);
    assert(memcmp(le_testbytes, le_testbytes_2, sizeof(le_testbytes)) == 0);

    // left-rotation ( 0x12345678 lrot 16bit -> 0x56781234)
    uint32_t r1=0xc0a8787e, r2=0x150f0fd8;
    assert(r2 == rotate(r1,5));

    // quarter round
    uint32_t a=0xe7e8c006, b=0xc4f9417d, c=0x6479b4b2, d=0x68c67137;
    quarterRound(a, b, c, d);
    assert(a==0xe876d72b && b==0x9361dfd5 && c==0xf1460244 && d==0x948541a3);

    // row round
    uint32_t test_state_rr[4][4] = {0x08521bd6, 0x1fe88837, 0xbb2aa576, 0x3aa26365,
                                    0xc54c6a5b, 0x2fc74c2f, 0x6dd39cc3, 0xda0a64f6,
                                    0x90a2f23d, 0x067f95a6, 0x06b35f61, 0x41e4732e,
                                    0xe859c100, 0xea4d84b7, 0x0f619bff, 0xbc6e965a};
    uint32_t rr_correct[4][4] =    {0xa890d39d, 0x65d71596, 0xe9487daa, 0xc8ca6a86,
                                    0x949d2192, 0x764b7754, 0xe408d9b9, 0x7a41b4d1,
                                    0x3402e183, 0x3c3af432, 0x50669f96, 0xd89ef0a8,
                                    0x0040ede5, 0xb545fbce, 0xd257ed4f, 0x1818882d};    
    rowRound(test_state_rr);
    assert(memcmp(test_state_rr, rr_correct, sizeof(rr_correct)) == 0);

    // column round
    uint32_t test_state_cl[4][4] = {0x08521bd6, 0x1fe88837, 0xbb2aa576, 0x3aa26365,
                                    0xc54c6a5b, 0x2fc74c2f, 0x6dd39cc3, 0xda0a64f6,
                                    0x90a2f23d, 0x067f95a6, 0x06b35f61, 0x41e4732e,
                                    0xe859c100, 0xea4d84b7, 0x0f619bff, 0xbc6e965a};
    uint32_t cl_correct[4][4] =    {0x8c9d190a, 0xce8e4c90, 0x1ef8e9d3, 0x1326a71a,
                                    0x90a20123, 0xead3c4f3, 0x63a091a0, 0xf0708d69,
                                    0x789b010c, 0xd195a681, 0xeb7d5504, 0xa774135c,
                                    0x481c2027, 0x53a8e4b5, 0x4c1f89c5, 0x3f78c9c8};
    columnRound(test_state_cl);
    assert(memcmp(test_state_cl, cl_correct, sizeof(cl_correct)) == 0);

    // double round
    uint32_t test_state_dr[4][4] = {0xde501066, 0x6f9eb8f7, 0xe4fbbd9b, 0x454e3f57,
                                    0xb75540d3, 0x43e93a4c, 0x3a6f2aa0, 0x726d6b36,
                                    0x9243f484, 0x9145d1e8, 0x4fa9d247, 0xdc8dee11,
                                    0x054bf545, 0x254dd653, 0xd9421b6d, 0x67b276c1};
    uint32_t dr_correct[4][4] =    {0xccaaf672, 0x23d960f7, 0x9153e63a, 0xcd9a60d0,
                                    0x50440492, 0xf07cad19, 0xae344aa0, 0xdf4cfdfc,
                                    0xca531c29, 0x8e7943db, 0xac1680cd, 0xd503ca00,
                                    0xa74b2ad6, 0xbc331c5c, 0x1dda24c7, 0xee928277};
    doubleRound(test_state_dr);
    assert(memcmp(test_state_dr, dr_correct, sizeof(dr_correct)) == 0);

    // keystreamBlock -----------------------------------------------------------------------------
    // save original matrix
    uint32_t matrix_save[4][4];
    memcpy(matrix_save, _matrix, sizeof(_matrix));

    uint8_t ksb_tst_bytes[64] =     {211,159,13,115,76,55,82,183,3,117,222,37,191,187,234,136,
                                    49,237,179,48,1,106,178,219,175,199,166,48,86,16,179,207,
                                    31,240,32,63,15,83,93,161,116,147,48,113,238,55,204,36,
                                    79,201,235,79,3,81,156,47,203,26,244,243,88,118,104,54};
    // fill matrix with test values
    for (uint8_t row=0, i=0; row<4; row++) {
        for (uint8_t col=0; col<4; col++) {
            _matrix[row][col] = littleEndianWordFromBytes(ksb_tst_bytes+i);
            i+=4;
        }
    }
    
    uint8_t out_block[64]={0};
    uint8_t out_block_correct[64] ={109,42,178,168,156,240,248,238,168,196,190,203,26,110,170,154,
                                    29,29,150,26,150,30,235,249,190,163,251,48,69,144,51,57,
                                    118,40,152,157,180,57,27,94,107,42,236,35,27,111,114,114,
                                    219,236,232,135,111,155,110,18,24,232,95,158,179,19,48,202};
    keyStreamBlock(out_block);
    cout << "in_block" << endl;
    for (int i=0; i<64; i++) {
        if (i!=0 && i%16==0) cout << "\n";
        cout << hex << setw(2) << (unsigned) ksb_tst_bytes[i] << " ";
    }
    cout << endl << "out_block" << endl;
    for (int i=0; i<64; i++) {
        if (i!=0 && i%16==0) cout << "\n";
        cout << hex << setw(2) << (unsigned) out_block[i] << " ";
    }
    cout << endl << "correct" << endl;
    for (int i=0; i<64; i++) {
        if (i!=0 && i%16==0) cout << "\n";
        cout << hex << setw(2) << (unsigned) out_block_correct[i] << " ";
    }
    cout << endl;
    assert(memcmp(out_block, out_block_correct, sizeof(out_block)) == 0);

    // restore original matrix
    memcpy(_matrix, matrix_save, sizeof(_matrix));
    // end of keystreamBlock test--------------------------------------------------------------------

}

void Salsa20::dbgPrintMatrix(const string str) {
    cout << str << endl;
    for(int i=0; i<4; i++){
        for(int j=0; j<4; j++){
            cout << hex << setw(8) << _matrix[i][j] <<" ";
        }
        cout << "\n";
    } cout << endl;
}