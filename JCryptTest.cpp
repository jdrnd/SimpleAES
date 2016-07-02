#include <iostream>
#include "jcrypt.h"

class JCryptTest{
    private:
        bool testArray(){
            JCrypt test;
            std::string testval = "stuff";
            uint8_t* vals = test.toArray(testval);
            for( int i = 0; i < testval.size(); i++ ){
                std::cout<< vals[i] << " ";
            }
            int val = vals[3];
            delete[] vals;
            return val == (int)'f';
        }

        void testBlockify(){
            JCrypt test;
            std::string stuff = "verylongstringthatiscertantlylongerthans16characters";
            uint8_t* vals = test.toArray(stuff);
            test.blockify(vals, stuff.size());

            for (int i = 0; i < stuff.size(); i++ ){
                for (int j = 0; j < 16; j++){
                    std::cout<< test.blocks[i][j] << " ";
                }
                std::cout << std::endl;
            }

        }
    public:
        int main(void){
            std::cout<< testArray() << "\n\n";
            testBlockify();
        }
};

int main(){
    JCryptTest Tester;
    Tester.main();
}

