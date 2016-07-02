#include <iostream>
#include "jcrypt.h"

class JCryptTest{
    private:


        bool testBlockify(){
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
    public:
        int main(void){
            std::cout << "Blockify Test: " << testBlockify() << std::endl;
        }
};

int main(){
    JCryptTest Tester;
    Tester.main();
}

