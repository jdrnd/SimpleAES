#include <iostream>
#include "SAES.h"
#include <time.h>
#include <assert.h>

class SAESTest{
    public:

        void test(){

            SAES crypter;
            std::string key = "longkeydfsgsdfgdysdfsgsdf";
            uint8_t* keyarr =  crypter.arrayKey(key);

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

            crypter.encryptText("longkeydfsgsdfgdysdfsgsdf");
            std::cout<< "Outputing encrypted text: ";
            for (int i = 0; i<32; i++){
                std::cout << crypter.blocks[i] << " ";
            }
            std::cout << "\n\n";

            crypter.decryptText("longkeydfsgsdfgdysdfsgsf");
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