#include <iostream>
#include "jcrypt.h"

class JCryptTest{
    public:

        void test(){
            JCrypt crypter;
            std::string key = "longkeydfsgsdfgdysdfsgsdf";
            uint8_t* keyarr =  crypter.arrayKey(key);

            for (int i = 0; i<16; i++){
                std::cout<< (int)keyarr[i] << " ";
            }
            std::cout<< "\n\n";

            crypter.setiv();

            for (int i = 0; i<16; i++){
                std::cout << crypter.iv[i] << " ";
            }

            crypter.blockify("datsdfsdfsfsdfsda");

            std::cout << "\n\n" << crypter.size << " ";
            for (int i = 0; i<32; i++){
                std::cout << (int)crypter.blocks[i] << " ";
            }

            crypter.encrypt("longkeydfsgsdfgdysdfsgsdf");
            std::cout<< "\n\n";
            for (int i = 0; i<32; i++){
                std::cout << (int)crypter.blocks[i] << " ";
            }

            crypter.decrypt("longkeydfsgsdfgdysdfsgsdf");
            std::cout<< "\n\n";
            for (int i = 0; i<32; i++){
                std::cout << (int)crypter.blocks[i] << " ";
            }



        }
};
int main(){
    JCryptTest tester;
    tester.test();
}