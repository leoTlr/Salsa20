#ifndef SALSA20_HPP
#define SALSA20_HPP

#include <string>
#include <vector>

/*  
    Implementation of Salsa20 stream cipher from D.J. Bernstein
    More info at: http://cr.yp.to/snuffle.html

    This implementation was made for exercise only and is not intended for productional use.
    I can not gurantee it from being free of mistakes or possible side-channel attacks.

    It was manually tested against some testvectors from included test_vectors_256 file
    (key and nonce interpreted as hex, stream = Salsa20::encryptBytes(input=nullvector))

    Threre are also tests of the encryption functions built in, with values from http://cr.yp.to/snuffle/spec.pdf

    (only tested on little endian system running Linux)
*/

class Salsa20 {
    
    uint32_t charsToLittleEndianWord(const std::string, size_t);
    uint32_t hexCharsToLittleEndianWord(const std::string, size_t);
    uint32_t littleEndianWordFromBytes(const uint8_t* bytes);
    void bytesFromLittleEndianWord(const uint32_t word, uint8_t* bytes);

    void doubleRound(uint32_t state[4][4]);
    void rowRound(uint32_t state[4][4]);
    void columnRound(uint32_t state[4][4]);
    void quarterRound(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d);

    uint32_t rotate(const uint32_t val, const uint8_t bits);
    void initMatrix(const uint32_t key[8], const size_t key_bitlen);
    void keyStreamBlock(uint8_t* out_block);

    // internal state, initialized with 0, will get changed in initMatrix and keyStreamBlock
    uint32_t _matrix[4][4] = {0};

public:

    /*  constructors for key as string or byte sequence
        in case of key string, if hex_key it will get interpreted as hex chars

        will accespt either 16 or 32 byte keys, exception will get thrown at different sizes */
    Salsa20(const std::string key, bool hex_key);
    Salsa20(std::vector<uint8_t> key);

    // set Nonce/IV, will also set counter to 0
    void setNonce(const std::string nonce_hex);
    void setNonce(const uint64_t nonce);

    /*  encrypt bytes from input into output
        input will stay unchanged */
    void encryptBytes(const uint8_t* input, uint8_t* output, const size_t num_bytes);
    void encryptBytes(const std::vector<uint8_t>& input, std::vector<uint8_t>& output);

    /*  test-cases for every (private) function of encryption process
    (values from http://cr.yp.to/snuffle/spec.pdf)  
    assertions on output of each test-case */
    void tests();
};

#endif // SALSA20_HPP