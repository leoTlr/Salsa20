#ifndef SALSA20_HPP
#define SALSA20_HPP

#include <iostream>
#include <string>
#include<vector>
#include <array>

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
    void incrementCounter();

    uint32_t _matrix[4][4] = {0};
    //std::array<std::array<uint32_t, 4>, 4> _matrix;
    uint32_t _stream_pos = 0;

public:

    Salsa20(const std::string key, bool hex_key);
    Salsa20(std::vector<uint8_t> key);

    void keyStreamBlock(uint8_t* out_block);

    void setNonce(const std::string nonce_hex);
    void setNonce(const uint64_t nonce);

    void setCounter(const std::string counter_hex);
    void setCounter(const uint64_t counter);

    void encryptBytes(uint8_t* input, uint8_t* output, const size_t num_bytes);

    void dbgPrintMatrix(const std::string str);


    void tests();
};

#endif // SALSA20_HPP