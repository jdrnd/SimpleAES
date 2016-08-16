#include <iostream>
#include "SAES.h"
#include <time.h>
#include <assert.h>

class SAESTest{
    private:
        SAES crypter;

        void testKeyDerrivation(){

            std::string key = "longkeydfsgsdfgdysdfsgsdf";
            uint8_t* keyarr = crypter.deriveKey(key);

            assert(keyarr[0] == (uint8_t)key[0]);
            assert(keyarr[15] == (uint8_t)key[15]);

            key =  "shorterpass";
            assert(keyarr[0] == uint8_t(key[0]));
            assert(keyarr[15] == 0);

            std::cout << "Outputting key: \n";
            for (int i = 0; i<15; i++){
                std::cout << keyarr[i];
            }
            std::cout << "\n\n";
        }

    public:

        void test(){




            for (int i = 0; i<16; i++){
                std::cout<< (int)keyarr[i] << " ";
            }
            std::cout<< "\n\n";

            crypter.setiv();
            std::cout << "Outputting IV" << " ";
            for (int i = 0; i<16; i++){
                std::cout << crypter.iv[i] << " ";
            }
            std::cout<< "\n\n";


            crypter.blockify("datsdfsdfsfsdfsda");
            std::cout << "Outputing block with size " << crypter.size << "  : ";
            for (int i = 0; i<32; i++){
                std::cout << crypter.blocks[i] << " ";
            }
            std::cout<< "\n\n";

            crypter.encryptText("longkeydfsgsdfgdysdfsgsdf",
                                (std::basic_string<char, char_traits < char>, allocator < char >> ()));
            std::cout<< "Outputing encrypted text: ";
            for (int i = 0; i<32; i++){
                std::cout << crypter.blocks[i] << " ";
            }
            std::cout << "\n\n";

            crypter.decryptText("longkeydfsgsdfgdysdfsgsf",
                                (std::basic_string<char, char_traits < char>, allocator < char >> ()));
            std::cout<< "Outputting decrypted text: ";
            for (int i = 0; i<32; i++){
                std::cout << crypter.blocks[i] << " ";
            }

            std::cout<<  "\n\n" << time(NULL) % 255;
        }
};
int main(){
    SAESTest tester;
    tester.test();
}