#include "jcrypt.h"

int* JCrypt::toArray(std::string data){
    int* bytearr = new int[data.size()];
    for (int i = 0; i< data.size(); i++){
        bytearr[i] = (int)data[i];
    }
    return bytearr;
}