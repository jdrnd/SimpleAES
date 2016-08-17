#include <iostream>
#include "SAES.h"
#include <time.h>
#include <assert.h>

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
            for (int i = 0; i<15; i++){
                std::cout << keyarr[i];
            }
            std::cout << "\n\n";
        }

        void testIVgeneration(){

            crypter.setiv();
            std::cout << "Outputting IV" << " ";
            for (int i = 0; i<16; i++){
                std::cout << crypter.iv[i] << " ";
            }
            std::cout<< "\n\n";
        }

        // Tests creation and padding of blocks with data
        void testBlockify(){
            crypter.blockify("datsdfsdfsfsdfsda");

            assert(crypter.blocks[0] == (uint8_t)'d');
            assert(crypter.blocks[16] == (uint8_t)'a');
            assert(crypter.blocks[18] == 0);
            assert(crypter.blocks[31] == 0);

            std::cout << "Outputing raw block with size " << crypter.size << ": ";
            for (int i = 0; i<32; i++){
                std::cout << (int)crypter.blocks[i] << " ";
            }
            std::cout<< "\n\n";
        }

        void testEnDeCrypt(){

            crypter.encryptText("key","long datajdfbshgkdsfjkdshfdjs,f");
            std::cout<< "Outputing encrypted text: ";
            for (int i = 0; i<48; i++){
                std::cout << crypter.blocks[i] << " ";
            }
            std::cout << "\n\n";


        }

    public:

        void runTests(){
            // Run test cases here
            testKeyDerrivation();
            testIVgeneration();
            testBlockify();
            testEnDeCrypt();

        }
};
int main(){
    SAESTest tester;
    tester.runTests();
}