#include <iostream>
#include "SAES.h"
#include <time.h>
#include <assert.h>
#include <iomanip>

class SAESTest{
    private:
        SAES crypter;

        // Tests key derivation, as well as key padding
        void testKeyDerrivation(){

            std::string key = "longkeydfsgsdfgdysdfsgsdf";
            uint8_t* keyarr = crypter.deriveKey(key);

            assert(keyarr[0] == (uint8_t)key[0]);
            assert(keyarr[15] == (uint8_t)key[15]);

            key =  "shorterpass";
            keyarr = crypter.deriveKey(key);

            assert(keyarr[0] == uint8_t(key[0]));
            assert(keyarr[15] == 0);

            std::cout << "Outputting key: ";
            std::string keyhex = crypter.bufferToHex(keyarr, 16);  // key is always 16 bytes long
            std::cout << keyhex << "\n";

            assert(keyhex.length() == 32);
            assert(keyhex == "73686f72746572706173730000000000");
        }

        void testIVgeneration(){

            crypter.setiv();

            uint8_t* tempIV = crypter.iv;
            std::string iv = crypter.bufferToHex(tempIV, 16);

            std::cout << "Outputting IV: ";
            std::cout << iv;
            std::cout<< "\n\n";

            assert(iv.length() == 32);
        }

        // Tests creation and padding of blocks with data
        void testBlockify(){
            crypter.blockify("datsdfsdfsfsdfsda");

            assert(crypter.blocks[0] == (uint8_t)'d');
            assert(crypter.blocks[16] == (uint8_t)'a');
            assert(crypter.blocks[18] == 0);
            assert(crypter.blocks[31] == 0);
        }

        void testByteSum(){
            crypter.blockify("Test String");
            uint16_t expected = 1079;

            uint16_t result = crypter.getByteSum();
            std::cout << "Bytesum for \"Test String\": " << result << "\n";

            assert(result == expected);
        }

        void testEncrypt(){
            std::string test = crypter.encryptText("key","long datajdfbshgkdsfjkdshfdjs,f");
            std::cout << "Outputting cyphertext: \n" << test << "\n\n";

            // TODO add regression test
        }

        void testDecrypt(){
            std::string test = crypter.encryptText("key", "long datajdfbshgkdsfjkdshfdjs,f");
            test = crypter.decryptText("key", test);
            std::cout << "\nOutputting decrypted text: \n" << test;
        }

    public:

        void runTests(){
            // Run test cases here
            testKeyDerrivation();
            testIVgeneration();
            testBlockify();
            testByteSum();
            testEncrypt();
            testDecrypt();

        }
};
int main(){
    SAESTest tester;
    tester.runTests();
}