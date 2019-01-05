#ifndef SALSA20_HPP
#define SALSA20_HPP

#include <string>
#include <vector>

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

//  abstract base class for Salsa20 and Chaha20 because they share much functionality
class SnuffleStreamCipher {

protected:

    SnuffleStreamCipher() = default; // other constructors should be used

    // implemented different in Salsa20 and Chacha20
    virtual void quarterRound(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) = 0;
    virtual void initMatrix(const uint32_t key[8], const size_t key_bytelen) = 0;
    virtual void doubleRound(uint32_t state[4][4]) = 0;
    virtual void incrementCounter() = 0;

    // used by both
    uint32_t charsToLittleEndianWord(const std::string, size_t);
    uint32_t hexCharsToLittleEndianWord(const std::string, size_t);
    uint32_t littleEndianWordFromBytes(const uint8_t* bytes);
    uint32_t rotate(const uint32_t val, const uint8_t bits);
    void bytesFromLittleEndianWord(const uint32_t word, uint8_t* bytes);
    void keyStreamBlock(uint8_t* out_block);

    // internal state and vars needed by both derived classes
    uint32_t _matrix[4][4] = {0};
    uint32_t _key[8];
    size_t  _inputKeyLength;

    /*  constructors for key as string or byte sequence
        in case of key string, if hex_key set it will get interpreted as hex chars

        will accept either 16 or 32 byte keys, exception will get thrown at different sizes
        or if hex_key set but not all chars are hex chars
        
        will set _key and _inputKeyLength

        Salsa20 and Chacha20 use these constructors
     */
    SnuffleStreamCipher(const std::string key, const bool hex_key);
    SnuffleStreamCipher(std::vector<uint8_t> key);

public:

    //  set Nonce/IV, will also set counter to 0
    virtual void setNonce(const std::string nonce_hex) = 0;
    virtual void setNonce(const uint64_t nonce) = 0;

    /*  start keystream generation after nr_blocks*64byte.
        use this to init keystream generation with counter > 0

        i.e.: using skipBlocks(3) before en-/decryption, the first call to keyStreamBlock() will yield the 4th block of keystream
        (-> start keystream at 3*64+1=193th byte instead of first)
        this way you can decrypt a part of a large stream without decrypting everything before this part

        TODO: implement for byte offset instead 64byte block offset */
    void skipBlocks(unsigned nr_blocks);

    /*  encrypt bytes from input into output
        input will stay unchanged */
    void encryptBytes(const uint8_t* input, uint8_t* output, const size_t num_bytes);
    void encryptBytes(const std::vector<uint8_t>& input, std::vector<uint8_t>& output);

    //  encrypt input in place
    void encryptBytes(std::vector<uint8_t>& input);

    virtual ~SnuffleStreamCipher() = default;
};


class Salsa20 : public SnuffleStreamCipher {

    Salsa20() = default; // other constructors should be used

    void initMatrix(const uint32_t key[8], const size_t key_bytelen);
    void quarterRound(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d);
    void rowRound(uint32_t state[4][4]);
    void columnRound(uint32_t state[4][4]); // different to Chacha20::columnRound
    void doubleRound(uint32_t state[4][4]);
    void incrementCounter();

public:

    /*  Base-class constructor will do input error checking
        and will set _key and _inputKeyLength
    */
    Salsa20(const std::string key_str, const bool hex_key) 
        : SnuffleStreamCipher(key_str, hex_key) { initMatrix(_key, _inputKeyLength);};
    Salsa20(std::vector<uint8_t> key)
        : SnuffleStreamCipher(key) { initMatrix(_key, _inputKeyLength);};

    //  set Nonce/IV, will also set counter to 0
    void setNonce(const std::string nonce_hex);
    void setNonce(const uint64_t nonce);
};


class Chacha20 : public SnuffleStreamCipher {

    Chacha20() = default; // other constructors should be used

    void initMatrix(const uint32_t key[8], const size_t key_bytelen);
    void quarterRound(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d);
    void diagonalRound(uint32_t state[4][4]);
    void columnRound(uint32_t state[4][4]); // different so Salsa20::columnRound
    void doubleRound(uint32_t state[4][4]);
    void incrementCounter();

public:

    /*  Base-class constructor will do input error checking
        and will set _key and _inputKeyLength
    */
    Chacha20(const std::string key, const bool hex_key)
        : SnuffleStreamCipher(key, hex_key) { initMatrix(_key, _inputKeyLength);};
    Chacha20(std::vector<uint8_t> key)
        : SnuffleStreamCipher(key) { initMatrix(_key, _inputKeyLength);};

    void setNonce(const std::string nonce_hex);
    void setNonce(const uint64_t nonce);
};

#endif // SALSA20_HPP