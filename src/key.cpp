#include "key.hpp"

Key::Key(const std::string& passphrase) {
    // Only use up to the first BLOCK_SIZE characters in the passphrase
    m_data.fill(0);
    for (uint i = 0; i < passphrase.length() && i < BLOCK_SIZE; i++)
    {
        m_data[i] = passphrase[i];
    }

    // If passphrase is shorter than the size, pad in the PKCS#7 style
    int32_t padding_len = BLOCK_SIZE - passphrase.length();
    if (padding_len > 0)
    {
        for (uint i = passphrase.length(); i < BLOCK_SIZE; i++)
        {
            m_data[i] = padding_len;
        }
    }
}

Key Key::CreateSecure(std::string& passphrase) {
    Key key = Key(passphrase);

    // Overwrite key with random data before deleting
    for (char& c : passphrase)
    {
        c = (char) (rand() % UINT8_MAX); 
    }
    passphrase.clear();

    return key;
}

Key::~Key() {
    // Explicitly do a full reset instead of a range-based loop
    for (size_t i = 0; i < BLOCK_SIZE; i++) {
        m_data[i] = (char) (rand() % UINT8_MAX);
    }
    m_data.fill(0);
}