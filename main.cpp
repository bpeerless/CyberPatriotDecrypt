#include <fstream>
#include <cryptopp/gcm.h>
#include <cryptopp/aes.h>
#include "CryptoPP/filters.h"
#include "CryptoPP/zlib.h"
#include <vector>
#include <iostream>
#include <random>
#include <streambuf>
#include <sstream>

static std::string ReadAllBytesAsLiteral(char const* filename) {
    std::ifstream ifs(filename, std::ios::binary);
    std::stringstream buffer;
    buffer << ifs.rdbuf();
    return buffer.str();
}

void generateRandomIV(CryptoPP::byte* iv) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    for(int i = 0; i < 12; ++i) {
        iv[i] = static_cast<CryptoPP::byte>(dis(gen));
    }
}

bool decrypt_file(const std::string& input_file, const std::string& output_file) {
    try {
        // Read the encrypted file
        std::ifstream ifs(input_file, std::ios::binary | std::ios::ate);
        std::ifstream::pos_type pos = ifs.tellg();
        std::vector<char> file_bytes(pos);
        ifs.seekg(0, std::ios::beg);
        ifs.read(file_bytes.data(), pos);

        char* file_buffer = file_bytes.data();

        // Extract the IV
        CryptoPP::byte iv[12];
        memcpy(iv, file_buffer, 12);

        // Define the key
        CryptoPP::byte key[] = {
            0xDE, 0x9F, 0xF2, 0x7D, 0x33, 0x6E, 0x45, 0xDE,
            0xB9, 0xE1, 0x18, 0xB2, 0xFD, 0x74, 0x9B, 0xC1
        };

        std::string decryptedtext;

        // Setup decryption
        CryptoPP::GCM<CryptoPP::AES>::Decryption gcmDecryption;
        gcmDecryption.SetKeyWithIV(key, sizeof(key), iv, 12);

        // Setup decompression
        CryptoPP::ZlibDecompressor* inflator = new CryptoPP::ZlibDecompressor(new CryptoPP::StringSink(decryptedtext));
        CryptoPP::AuthenticatedDecryptionFilter df(gcmDecryption, inflator);

        // Process the data
        df.Put((const CryptoPP::byte*)(file_buffer + 12), file_bytes.size() - 12);

        // Write the raw decrypted data in binary mode
        std::ofstream out(output_file, std::ios::binary);
        out.write(decryptedtext.data(), decryptedtext.size());
        out.close();

        return true;
    }
    catch (const std::exception& e) {
        std::cerr << "Decryption error: " << e.what() << std::endl;
        return false;
    }
}

bool encrypt_file(const std::string& input_file, const std::string& output_file) {
    try {
        // Read file preserving literal characters
        std::string input_content = ReadAllBytesAsLiteral(input_file.c_str());

        // Generate random IV
        CryptoPP::byte iv[12];
        generateRandomIV(iv);

        // Define the key (same as decryption)
        CryptoPP::byte key[] = {
            0xDE, 0x9F, 0xF2, 0x7D, 0x33, 0x6E, 0x45, 0xDE,
            0xB9, 0xE1, 0x18, 0xB2, 0xFD, 0x74, 0x9B, 0xC1
        };

        std::string compressedtext;
        std::string encryptedtext;

        // Compress first
        CryptoPP::ZlibCompressor compressor(new CryptoPP::StringSink(compressedtext));
        compressor.Put((const CryptoPP::byte*)input_content.data(), input_content.size());
        compressor.MessageEnd();

        // Setup encryption
        CryptoPP::GCM<CryptoPP::AES>::Encryption gcmEncryption;
        gcmEncryption.SetKeyWithIV(key, sizeof(key), iv, 12);

        // Create encryption filter
        CryptoPP::AuthenticatedEncryptionFilter ef(gcmEncryption, new CryptoPP::StringSink(encryptedtext));
        ef.Put((const CryptoPP::byte*)compressedtext.data(), compressedtext.size());
        ef.MessageEnd();

        // Write IV and encrypted data to output file
        std::ofstream out(output_file, std::ios::binary);
        out.write(reinterpret_cast<const char*>(iv), 12);
        out.write(encryptedtext.data(), encryptedtext.size());
        out.close();

        return true;
    }
    catch (const std::exception& e) {
        std::cerr << "Encryption error: " << e.what() << std::endl;
        return false;
    }
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <mode> <input_file>" << std::endl;
        std::cerr << "Modes: encrypt, decrypt" << std::endl;
        return 1;
    }

    std::string mode = argv[1];
    std::string input_file = argv[2];
    std::string base_name = input_file.substr(0, input_file.find_last_of('.'));
    std::string timestamp = std::to_string(time(0));

    if (mode == "decrypt") {
        std::string output_file = base_name + "-" + timestamp + ".xml";
        if (decrypt_file(input_file, output_file)) {
            std::cout << "Decrypted data saved to: " << output_file << std::endl;
            return 0;
        }
    }
    else if (mode == "encrypt") {
        std::string output_file = base_name + "-" + timestamp + ".dat";
        if (encrypt_file(input_file, output_file)) {
            std::cout << "Encrypted data saved to: " << output_file << std::endl;
            return 0;
        }
    }
    else {
        std::cerr << "Invalid mode. Use 'encrypt' or 'decrypt'" << std::endl;
        return 1;
    }

    return 1;
}