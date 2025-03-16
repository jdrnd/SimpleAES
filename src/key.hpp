#include <array>
#include <string>

#include "types.h"

class Key {
public:
    Key() = delete;
    // Securly overwrites and clears the key data
    ~Key();

    // The preferred method of constructing a key, which securely overwrites the input passphrase
    static Key CreateSecure(std::string& passphrase);

    const byte& operator[](int index) { return m_data[index]; }
    const byte* data() { return m_data.data(); }

private:
    // Constructors should not have side effects, so CreateSecure is the prefered method
    Key(const std::string& passphrase);

    std::array<byte, BLOCK_SIZE> m_data;
};