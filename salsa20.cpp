#include <cstring> // memcpy
#include <cassert>
#include <algorithm> // std::all_of()
#include <sstream> // hex str to ulong conversion
#include <stdlib.h> // strtoul()
#include <stdint.h> // uintX_t types
#include <stdexcept> //std::length_error, std::invalid_argument

#include "salsa20.hpp"

using namespace std;

/*  
    Implementation of Salsa20 and Chacha20 stream ciphers from D.J. Bernstein
    More info at: http://cr.yp.to/snuffle.html and https://cr.yp.to/chacha.html

    These implementations were made for exercise only and are not intended for productional use.
    I can not gurantee it from being free of mistakes or possible side-channel attacks.

    Salsa20 was manually tested against some testvectors from included salsa20_vectors_256 file
    (key and nonce interpreted as hex, stream = Salsa20::encryptBytes(input=nullvector))

    Chacha20 was manually tested against testvectors in chacha20_vectors_256

    (only tested on little endian system running Linux)
*/


// ------ Abstract base class with shared functionality--------------------------------------------

/*  Constructor for key as string.
    If hex_key is set, iterpreted as hex chars, else ascii
    Only 16 or 32 byte keys allowed, else an Exception is thrown
    will also throw exception if hex_key is set but not all chars are hex   
*/ 
SnuffleStreamCipher::SnuffleStreamCipher(const string key_str, const bool hex_key) {

    switch (hex_key) {

    case false: // interpret as ascii

        if (!(key_str.size()==16 || key_str.size()==32))
            throw length_error("Keylength has to be 16 or 32 byte"); 

        // 4 keystr chars -> one 32bit word
        for (uint8_t i=0, j=0; i<key_str.length(); i+=4, j++)
            _key[j] = charsToLittleEndianWord(key_str, i);

        // if short key, copy same key in other half of key blocks
        if (key_str.length() == 32) { 
            memcpy(&_key[4], &_key[0], sizeof(_key[0])*4);
            _inputKeyLength = 16;
        } else {
            _inputKeyLength = 32;
        }
        break;

    case true: // interpret as hex string

        if (!(key_str.size()==32 || key_str.size()==64))
            throw length_error("Keylength has to be 16 or 32 byte (32 or 64 hex chars, no 0x prefix)"); 

        if (!(all_of(key_str.begin(), key_str.end(), ::isxdigit)))
            throw invalid_argument("if hex_key is set key needs to contain only hex chars (also no 0x prefix)");

        // 8 keystr hex chars -> one 32bit word
        for (uint8_t i=0, j=0; i<key_str.length(); i+=8, j++)
            _key[j] = hexCharsToLittleEndianWord(key_str, i);

        // if short key, copy same key in other half of key blocks
        if (key_str.length() == 32) { 
            memcpy(&_key[4], &_key[0], sizeof(_key[0])*4);
            _inputKeyLength = 16;
        } else
            _inputKeyLength = 32;
    }    
}

/*  Constructor for key as bytevector
    Takes a std::vector<uint8_t> with bytes used as key
    Only 16 or 32 byte keys allowed, else an Exception is thrown    
*/ 
SnuffleStreamCipher::SnuffleStreamCipher(const vector<uint8_t> key) {
    if (!(key.size()==16 || key.size()==32))
        throw length_error("Keylength has to be 16 or 32 byte");

    uint32_t key_words[8];

    for (uint8_t i=0, j=0; (i < (key.size() / 4) && j < key.size()); i++, j+=4)
        key_words[i] = littleEndianWordFromBytes(&key[j]);

    // if keysize 16 byte duplicate into the remaining 16 byte
    if (key.size() == 16) {
        memcpy(&key_words[4], &key_words[0], 4*sizeof(key_words));
        _inputKeyLength = 16;
    } else
        _inputKeyLength = 32;
};

// create a 32bit little endian word from four bytes
uint32_t SnuffleStreamCipher::littleEndianWordFromBytes(const uint8_t* bytes) {
    return  bytes[0] + \
            ((uint_fast16_t) bytes[1] <<  8) + \
            ((uint_fast32_t) bytes[2] << 16) + \
            ((uint_fast32_t) bytes[3] << 24);
};

// puts a 32bit word into the four bytes pointed to
void SnuffleStreamCipher::bytesFromLittleEndianWord(const uint32_t word, uint8_t* bytes) {
    bytes[0] = word;
    bytes[1] = word >> 8;
    bytes[2] = word >> 16;
    bytes[3] = word >> 24;
};

// left rotation by bits bit
uint32_t SnuffleStreamCipher::rotate(const uint32_t val, const uint8_t bits) {
    return (val << bits) | (val >> (32 - bits));
}

// generate one block (64byte) of keystream
void SnuffleStreamCipher::keyStreamBlock(uint8_t* out_block) {

    // make copy of matrix as we need the original matrix later 
    static uint32_t state[4][4];
    memcpy(&state, &_matrix, sizeof(_matrix));
    
    // 10 double-rounds -> 20 rounds
    for (uint8_t i=0; i<20; i+=2)
        doubleRound(state);

    // add original state to processed state (normal addition mod 2**32)
    for (uint8_t row=0; row<4; row++) 
        for (uint8_t col=0; col<4; col++)
            state[row][col] += _matrix[row][col];

    // split state into bytes and fill out_block
    for (uint8_t row=0, i=0; row<4; row++) {
        for (uint8_t col=0; col<4; col++) {
            bytesFromLittleEndianWord(state[row][col], out_block+i);
            i+=4;
        }
    }

    incrementCounter();
}

/*  start keystream generation after nr_blocks*64byte.
    use this to init keystream generation with counter > 0

    i.e.: using skipBlocks(3) before en-/decryption, the first call to keyStreamBlock() will yield the 4th block of keystream
    (-> start keystream at 3*64+1=193th byte instead of first)
    this way you can decrypt a part of a large stream without decrypting everything before this part

    TODO: implement for byte offset instead (64byte) block offset */
void SnuffleStreamCipher::skipBlocks(unsigned nr_blocks) {
    for (; nr_blocks > 0; nr_blocks--)
        incrementCounter();
}

// encrypt num_bytes bytes from input into output
void SnuffleStreamCipher::encryptBytes(const uint8_t* input, uint8_t* output, const size_t num_bytes) {
    assert(input != nullptr && output != nullptr);
    if (num_bytes==0) return;

    // allocate once and reuse it
    static uint8_t block_buf[64] ={0};
    
    for (size_t i=0; i<num_bytes; i++) {

        // get new block of keystream after every 64 bytes
        if (i%64 == 0) 
            keyStreamBlock(block_buf);
        
        // xor input byte with keystream byte incrementing pointers
        *(output++) = block_buf[(i%64)] ^ *(input++);
    }
}

// wrapper to use encrytBytes with std::vector
void SnuffleStreamCipher::encryptBytes(const vector<uint8_t>& input, vector<uint8_t>& output) {
    if (input.size() == 0) return;

    output.reserve(input.size());
    encryptBytes(input.data(), output.data(), input.size());
}

// wrapper to use encryptBytes with std::vector, encrypting input in place
void SnuffleStreamCipher::encryptBytes(vector<uint8_t>& input) {
    if (input.size() == 0) return;

    encryptBytes(input.data(), input.data(), input.size());
}

// interpret string as hex and put values in littleEndianWordFromBytes()
uint32_t SnuffleStreamCipher::hexCharsToLittleEndianWord(const string hex_str, size_t start_pos) {
    assert(all_of(hex_str.begin(), hex_str.end(), ::isxdigit));
    assert(start_pos+8 <= hex_str.length());

    uint8_t bytes[4];
    for (uint8_t i=0; i<4; i++)
        bytes[i] = stoul(hex_str.substr((start_pos+(2*i)), 2), nullptr, 16);   

    return littleEndianWordFromBytes(bytes);
}

// take the numerical values of four chars and put them into littleEndianWordFomBytes()
uint32_t SnuffleStreamCipher::charsToLittleEndianWord(const string str, size_t start_pos) {
    assert((start_pos+4) <= str.length());

    return littleEndianWordFromBytes((const uint8_t *) (&(str.c_str()[start_pos])));
}


// ------ Salsa20 specific -----------------------------------------------------------------------

/*  initialize internal matrix using uint32_t key[8]
    constants depend on keylength

    Nonce and Counter 0 by default
    use setNonce() and setCounter()
*/
void Salsa20::initMatrix(const uint32_t key[8], const size_t keylen) {
    assert(sizeof(&key) == 8);
    assert(keylen == 16 || keylen == 32);    

    static const char constants_32byte_key[17] = "expand 32-byte k";
    static const char constants_16byte_key[17] = "expand 16-byte k";

    const char* constants;

    // decide which constants to use depending on key length
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
    // 2 * nonce (default 0)

    // 2 * counter (default 0)
    _matrix[2][2] = littleEndianWordFromBytes((const uint8_t *) (constants+8)); 
    _matrix[2][3] = key[4];

    _matrix[3][0] = key[5];
    _matrix[3][1] = key[6];
    _matrix[3][2] = key[7];
    _matrix[3][3] = littleEndianWordFromBytes((const uint8_t *) (constants+12));
}

// main function of encryption process
void Salsa20::quarterRound(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
    b ^= rotate((a+d), 7);
    c ^= rotate((b+a), 9);
    d ^= rotate((c+b), 13);
    a ^= rotate((d+c), 18);
}

/*  quarterround on each column.
    Salsa20 halso has a columnRound that uses all elements in a column as input to quarterRound,
    but feeds the elements into quarterRound in a different order */
void Salsa20::columnRound(uint32_t state[4][4]) {
    quarterRound(state[0][0], state[1][0], state[2][0], state[3][0]);
    quarterRound(state[1][1], state[2][1], state[3][1], state[0][1]);
    quarterRound(state[2][2], state[3][2], state[0][2], state[1][2]);
    quarterRound(state[3][3], state[0][3], state[1][3], state[2][3]);
}

// quarter-round on each row
void Salsa20::rowRound(uint32_t state[4][4]) {
    quarterRound(state[0][0], state[0][1], state[0][2], state[0][3]);
    quarterRound(state[1][1], state[1][2], state[1][3], state[1][0]);
    quarterRound(state[2][2], state[2][3], state[2][0], state[2][1]);
    quarterRound(state[3][3], state[3][0], state[3][1], state[3][2]);
}

// first column, then row-round
void Salsa20::doubleRound(uint32_t state[4][4]) {
    columnRound(state);
    rowRound(state);
}

void Salsa20::incrementCounter() {
    _matrix[2][0]++;
    if (!_matrix[2][0])
        _matrix[2][1]++; 
}

// set nonce to nonce, set counter to 0 as nonce is used as IV
void Salsa20::setNonce(const uint64_t nonce) {
    
    _matrix[1][2] = (uint32_t) ((nonce & 0xffffffff00000000) >> 32);
    _matrix[1][3] = (uint32_t) ((nonce & 0x00000000ffffffff) >> 32);
    _matrix[2][0] = 0;
    _matrix[2][1] = 0;
}

/*  nonce/IV interpreted as hex chars
    set nonce to (uint32_t) hex_str and counter to 0 as nonce is used as IV
    will throw exceptions if length other than 8 byte if non-hex chars in key (also if 0x prefix)   */
void Salsa20::setNonce(const string hex_str) {
    if (!(hex_str.size()==16))
        throw length_error("Nonce has to be 8 byte (16 hex chars, no 0x prefix)"); 

    if (!(all_of(hex_str.begin(), hex_str.end(), ::isxdigit)))
        throw invalid_argument("nonce needs to contain only hex chars (also no 0x prefix)");

    _matrix[1][2] = hexCharsToLittleEndianWord(hex_str, 0);
    _matrix[1][3] = hexCharsToLittleEndianWord(hex_str, 8);
    _matrix[2][0] = 0;
    _matrix[2][1] = 0;
}


// ------ Chacha20 specific ----------------------------------------------------------------------

void Chacha20::initMatrix(const uint32_t key[8], const size_t keylen) {
    assert(sizeof(&key) == 8);
    assert(keylen == 16 || keylen == 32);    

    static const char constants_32byte_key[17] = "expand 32-byte k";
    static const char constants_16byte_key[17] = "expand 16-byte k";

    const char* constants;

    // decide which constants to use depending on key length
    if (keylen == 32)
        constants = constants_32byte_key;
    else if (keylen == 16)
        constants = constants_16byte_key;

    _matrix[0][0] = littleEndianWordFromBytes((const uint8_t *) constants);
    _matrix[0][1] = littleEndianWordFromBytes((const uint8_t *) (constants+4));
    _matrix[0][2] = littleEndianWordFromBytes((const uint8_t *) (constants+8)); 
    _matrix[0][3] = littleEndianWordFromBytes((const uint8_t *) (constants+12));

    _matrix[1][0] = key[0];
    _matrix[1][1] = key[1];
    _matrix[1][2] = key[2];
    _matrix[1][3] = key[3];
    
    _matrix[2][0] = key[4];
    _matrix[2][1] = key[5];    
    _matrix[2][2] = key[6];
    _matrix[2][3] = key[7];

    // _matrix[3][0 to 4] == 2 words counter, 2 words nonce
}

void Chacha20::quarterRound(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
    a += b; d ^= a; d = rotate(d, 16);
    c += d; b ^= c; b = rotate(b, 12);
    a += b; d ^= a; d = rotate(d, 8);
    c += d; b ^= c; b = rotate(b, 7);
}

/*  quarterround on each column.
    Salsa20 halso has a columnRound that uses all elements in a column as input to quarterRound,
    but feeds the elements into quarterRound in a different order */
void Chacha20::columnRound(uint32_t state[4][4]) {
    quarterRound(state[0][0], state[1][0], state[2][0], state[3][0]);
    quarterRound(state[0][1], state[1][1], state[2][1], state[3][1]);
    quarterRound(state[0][2], state[1][2], state[2][2], state[3][2]);
    quarterRound(state[0][3], state[1][3], state[2][3], state[3][3]);
}

// four diagonal quarter rounds
void Chacha20::diagonalRound(uint32_t state[4][4]) {
    quarterRound(state[0][0], state[1][1], state[2][2], state[3][3]);
    quarterRound(state[0][1], state[1][2], state[2][3], state[3][0]);
    quarterRound(state[0][2], state[1][3], state[2][0], state[3][1]);
    quarterRound(state[0][3], state[1][0], state[2][1], state[3][2]);
}

// first column, then diagonal-round
void Chacha20::doubleRound(uint32_t state[4][4]) {
    columnRound(state);
    diagonalRound(state);
}

void Chacha20::incrementCounter() {
    _matrix[3][0]++;
    if (!_matrix[3][0])
        _matrix[3][1]++; 
}

// set nonce to nonce, set counter to 0 as nonce is used as IV
void Chacha20::setNonce(const uint64_t nonce) {
    
    _matrix[3][0] = 0;
    _matrix[3][1] = 0;
    _matrix[3][2] = (uint32_t) ((nonce & 0xffffffff00000000) >> 32);
    _matrix[3][3] = (uint32_t) ((nonce & 0x00000000ffffffff) >> 32);
}

/*  nonce/IV interpreted as hex chars
    set nonce to (uint32_t) hex_str and counter to 0 as nonce is used as IV
    will throw exceptions if length other than 8 byte if non-hex chars in key (also if 0x prefix)   */
void Chacha20::setNonce(const string hex_str) {
    if (!(hex_str.size()==16))
        throw length_error("Nonce has to be 8 byte (16 hex chars, no 0x prefix)"); 

    if (!(all_of(hex_str.begin(), hex_str.end(), ::isxdigit)))
        throw invalid_argument("nonce needs to contain only hex chars (also no 0x prefix)");

    _matrix[3][0] = 0;
    _matrix[3][1] = 0;
    _matrix[3][2] = hexCharsToLittleEndianWord(hex_str, 0);
    _matrix[3][3] = hexCharsToLittleEndianWord(hex_str, 8);
}