#include <iostream>
#include "jcrypt.h"

class JCryptTest{
    private:


        /*bool testBlockify(){
            JCrypt test;
            std::string stuff = "verylongstringthatiscertantlylongerthans16characters";
            test.blockify(stuff);

            for (int i = 0; i < (stuff.size()/16)+1; i++ ){
                for (int j = 0; j < 16; j++){
                    std::cout<< test.blocks[i][j] << " ";
                }
                std::cout << std::endl;
            }

            return (test.blocks[0][0] == (uint8_t)'v' && test.blocks[3][7] == 0);
        }

        bool testEncrypt(){
            JCrypt test;
            std::string stuff = "verylongstringthatiscertantlylongerthans16characters";
            test.blockify(stuff);
            test.encrypt("yomomma");

            for (int i = 0; i < (stuff.size()/16)+1; i++ ){
                for (int j = 0; j < 16; j++){
                    std::cout<< test.blocks[i][j] << " ";
                }
                std::cout << std::endl;
            }
            std::cout << std::endl << std::endl;

            test.decrypt("yomomma");
            for (int i = 0; i < (stuff.size()/16)+1; i++ ){
                for (int j = 0; j < 16; j++){
                    std::cout<< test.blocks[i][j] << " ";
                }
                std::cout << std::endl;
            }
            std::cout << std::endl << std::endl;

            test.encrypt("yomomma");
            for (int i = 0; i < (stuff.size()/16)+1; i++ ){
                for (int j = 0; j < 16; j++){
                    std::cout<< (char)test.blocks[i][j] << " ";
                }
                std::cout << std::endl;
            }
            std::cout << std::endl << std::endl;

            test.decrypt("yomomma");
            for (int i = 0; i < (stuff.size()/16)+1; i++ ){
                for (int j = 0; j < 16; j++){
                    std::cout<< (char)test.blocks[i][j] << " ";
                }
                std::cout << std::endl;
            }
            return true;
        }*/
        void test(){
            JCrypt test;
            std::string stuff = "verylongstringthatiscertantlylongerthans16characters";
            test.blockify2(stuff);

            for (int i = 0; i < test.size; i++ ) {
                std::cout<< test.blocks2[i];
            }
        }

    public:
        int main(void){
            //std::cout << "Blockify Test: " << testBlockify() << std::endl;
            //std::cout << "Ecrypt test: " << testEncrypt();
            test();
        }
};

int main(){
    JCryptTest Tester;
    Tester.main();
}

