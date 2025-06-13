#include <iostream>
#include <vector>
#include <string>
#include <cstdint>
#include <cstring>

#include "AURA.h"

// helper function to print a vector for debugging
void print_vector(const std::string& title, const std::vector<unsigned char>& data) {
    std::cout << title << " (size: " << data.size() << "): ";
    for(size_t i = 0; i < data.size() && i < 32; ++i) {
        std::cout << std::hex << (int)data[i] << " ";
    }
    if (data.size() > 32) std::cout << "...";
    std::cout << std::dec << std::endl;
}

int main() {
    std::cout << "--- AURA Library Standalone Test ---" << std::endl;

    // 1. SETUP: define test data
    std::vector<unsigned char> master_key(AURA_Processor::KEY_SIZE, 0xAB);
    
    // prepare sample payload with header format
    std::string filename = "report.txt";
    std::string file_content = "This is the secret content of the file.";
    
    // header: [8-byte total length][2-byte filename length]
    uint16_t filename_len = static_cast<uint16_t>(filename.length());
    uint64_t total_payload_len = sizeof(uint64_t) + sizeof(uint16_t) + filename_len + file_content.length();

    std::vector<unsigned char> original_payload;
    original_payload.resize(total_payload_len);

    // construct the byte vector
    unsigned char* ptr = original_payload.data();
    std::memcpy(ptr, &total_payload_len, sizeof(uint64_t));
    ptr += sizeof(uint64_t);
    std::memcpy(ptr, &filename_len, sizeof(uint16_t));
    ptr += sizeof(uint16_t);
    std::memcpy(ptr, filename.c_str(), filename_len);
    ptr += filename_len;
    std::memcpy(ptr, file_content.c_str(), file_content.length());
    
    print_vector("Original Payload", original_payload);

    // 1a. PRE-FLIGHT CHECK: Test the pixel calculation method
    std::cout << "\n--- Testing Pixel Calculation ---" << std::endl;
    size_t required_pixels = AURA_Processor::calculate_required_pixels(original_payload.size());
    size_t expected_pixels = original_payload.size() + AURA_Processor::AUTH_TAG_SIZE;

    if (required_pixels != expected_pixels) {
        std::cerr << "FAILURE: calculate_required_pixels() returned " << required_pixels
                  << ", but " << expected_pixels << " were expected." << std::endl;
        return 1;
    }
    std::cout << "SUCCESS: calculate_required_pixels() returned correct value: " << required_pixels << std::endl;
    

    // create a dummy in-memory image buffer
    const size_t width = 100;
    const size_t height = 100;
    std::vector<unsigned char> image_data(width * height * 4, 0xEE);
    AURA_ImageBuffer image_buffer { image_data.data(), width, height };
    
    // 2. ENCRYPTION
    std::cout << "\n--- Encrypting ---" << std::endl;
    AURA_Processor aura(master_key);
    AURA_Result encrypt_result = aura.encrypt(original_payload, image_buffer);

    if (encrypt_result != AURA_Result::Success) {
        std::cerr << "Encryption FAILED with code: " << static_cast<int>(encrypt_result) << std::endl;
        return 1;
    }
    std::cout << "Encryption successful." << std::endl;

    // 3. DECRYPTION
    std::cout << "\n--- Decrypting ---" << std::endl;
    std::vector<unsigned char> decrypted_payload;
    AURA_Result decrypt_result = aura.decrypt(decrypted_payload, image_buffer);

    if (decrypt_result != AURA_Result::Success) {
        std::cerr << "Decryption FAILED with code: " << static_cast<int>(decrypt_result) << std::endl;
        return 1;
    }
    std::cout << "Decryption successful." << std::endl;
    print_vector("Decrypted Payload", decrypted_payload);

    // 4. VERIFICATION
    std::cout << "\n--- Verifying ---" << std::endl;
    if (original_payload == decrypted_payload) {
        std::cout << "SUCCESS: Decrypted data matches original data." << std::endl;
    } else {
        std::cerr << "FAILURE: Decrypted data does NOT match original data." << std::endl;
        return 1;
    }

    return 0;
}