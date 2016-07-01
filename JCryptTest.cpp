#include <iostream>
#include "jcrypt.h"

class JCryptTest{
    private:
        bool testArray(){
            JCrypt test;
            std::string testval = "stuff";
            int * vals = test.toArray(testval);
            for( int i = 0; i < testval.size(); i++ ){
                std::cout<< vals[i] << " ";
            }
            return true;
        }
    public:
        int main(void){
            testArray();
        }
};

int main(){
    JCryptTest Tester;
    Tester.main();
}

