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

            std::cout << "Outputting key: \n";
            std::string keyhex = crypter.bufferToHex(keyarr, 16);
            for (int i = 0; i<16; i++){
                std::cout << (int)keyarr[i];
            }
            std::cout << "\n" << keyhex << "\n\n";

            assert(keyhex.length() == 32);
        }

        void testIVgeneration(){

            crypter.setiv();

            // Do it thise way as direct access causes error
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

            std::cout << "Outputing raw block with size " << crypter.size << ": ";
            uint8_t* blocks = crypter.blocks;
            int len = crypter.size;

            std::string blockdata = crypter.bufferToHex(blocks, len);
            assert(blockdata.length() == (len*2));

            std::cout << blockdata << "\n\n";

        }

        void testEncrypt(){

            std::string test = crypter.encryptText("key","long datajdfbshgkdsfjkdshfdjs,f");
            std::cout << "Outputting char representation of cyphertext: \n" << test << "\n\n";

            int cypherlen = test.length();

            std::cout << "Outputing cyphertext, hex representation: \n";
            for (int i = 0; i < cypherlen; i++){
                std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)test[i];
            }
            std::cout << "\n";

            for (int i = 0; i < cypherlen; i++){
                std::cout << (int)test[i];
            }
            std::cout << "\n";
            // #TODO add regression test test
        }

        void testDecrypt(){

            std::string test = crypter.encryptText("key","long datajdfbshgkdsfjkdshfdjs,f");
            test = crypter.decryptText("key", test);
            std::cout << "Outputting decrypted text: \n" << test;
        }

    public:

        void runTests(){
            // Run test cases here
            testKeyDerrivation();
            testIVgeneration();
            testBlockify();
            testEncrypt();
            testDecrypt();

        }
};
int main(){
    SAESTest tester;
    tester.runTests();
}