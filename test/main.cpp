#include <iostream>
#include <vector>
#include <string>
#include <cstdint>
#include <cstring>
#include <functional>
#include <iomanip>

#include "AURA.h"

// helper to write a 64-bit integer in Big Endian format
void write_big_endian_uint64(unsigned char* buffer, uint64_t value) {
    buffer[0] = (value >> 56) & 0xFF;
    buffer[1] = (value >> 48) & 0xFF;
    buffer[2] = (value >> 40) & 0xFF;
    buffer[3] = (value >> 32) & 0xFF;
    buffer[4] = (value >> 24) & 0xFF;
    buffer[5] = (value >> 16) & 0xFF;
    buffer[6] = (value >> 8) & 0xFF;
    buffer[7] = (value >> 0) & 0xFF;
}

// helper to write a 16-bit integer in Big Endian format
void write_big_endian_uint16(unsigned char* buffer, uint16_t value) {
    buffer[0] = (value >> 8) & 0xFF;
    buffer[1] = (value >> 0) & 0xFF;
}

// helper function to print a vector for debugging
void print_vector(const std::string& title, const std::vector<unsigned char>& data) {
    std::cout << "    " << title << " (size: " << data.size() << "): ";
    for(size_t i = 0; i < data.size() && i < 32; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)data[i] << " ";
    }
    if (data.size() > 32) std::cout << "...";
    std::cout << std::dec << std::endl;
}

// simple test runner
void run_test(const std::string& test_name, std::function<bool()> test_func) {
    std::cout << "[RUNNING] " << test_name << std::endl;
    if (test_func()) {
        std::cout << "[ PASS  ] " << test_name << std::endl;
    } else {
        std::cout << "[ FAIL  ] " << test_name << std::endl;
    }
    std::cout << "------------------------------------------------------------" << std::endl;
}

// verifies the standard encrypt -> decrypt cycle
bool test_happy_path() {
    std::vector<unsigned char> master_key(AURA_Processor::KEY_SIZE, 0xAB);
    
    std::string filename = "report.txt";
    std::string file_content = "This is the secret content of the file.";
    
    uint16_t filename_len = static_cast<uint16_t>(filename.length());
    uint64_t total_payload_len = sizeof(uint64_t) + sizeof(uint16_t) + filename_len + file_content.length();

    std::vector<unsigned char> original_payload(total_payload_len);
    unsigned char* ptr = original_payload.data();
    
    // construct header with big endian serialization to match cZip's QDataStream
    write_big_endian_uint64(ptr, total_payload_len);
    ptr += sizeof(uint64_t);
    write_big_endian_uint16(ptr, filename_len);
    ptr += sizeof(uint16_t);
    std::memcpy(ptr, filename.c_str(), filename_len);
    ptr += filename_len;
    std::memcpy(ptr, file_content.c_str(), file_content.length());
    
    print_vector("Original Payload", original_payload);

    const size_t width = 100, height = 100;
    std::vector<unsigned char> image_data(width * height * 4, 0xEE);
    AURA_ImageBuffer image_buffer { image_data.data(), width, height };
    
    AURA_Processor aura(master_key);
    if (aura.encrypt(original_payload, image_buffer) != AURA_Result::Success) {
        std::cerr << "    ERROR: Encryption failed unexpectedly." << std::endl;
        return false;
    }

    std::vector<unsigned char> decrypted_payload;
    if (aura.decrypt(decrypted_payload, image_buffer) != AURA_Result::Success) {
        std::cerr << "    ERROR: Decryption failed unexpectedly." << std::endl;
        return false;
    }
    
    print_vector("Decrypted Payload", decrypted_payload);
    
    if (original_payload != decrypted_payload) {
        std::cerr << "    ERROR: Decrypted data does not match original." << std::endl;
        return false;
    }
    
    return true;
}

// verifies that decryption fails with an incorrect key
bool test_wrong_key_failure() {
    std::vector<unsigned char> master_key_A(AURA_Processor::KEY_SIZE, 0xAA);
    std::vector<unsigned char> master_key_B(AURA_Processor::KEY_SIZE, 0xBB);
    std::vector<unsigned char> payload = { 't', 'e', 's', 't' };

    const size_t width = 10, height = 10;
    std::vector<unsigned char> image_data(width * height * 4, 0xEE);
    AURA_ImageBuffer image_buffer { image_data.data(), width, height };

    AURA_Processor aura_A(master_key_A);
    aura_A.encrypt(payload, image_buffer);

    // use a different processor with a different key for decryption
    AURA_Processor aura_B(master_key_B);
    std::vector<unsigned char> decrypted_payload;
    AURA_Result result = aura_B.decrypt(decrypted_payload, image_buffer);

    if (result != AURA_Result::Error_Authentication_Failed) {
        std::cerr << "    ERROR: Expected Error_Authentication_Failed, but got code " << static_cast<int>(result) << std::endl;
        return false;
    }
    return true;
}

// verifies that tampered image data fails authentication
bool test_tampered_data_failure() {
    std::vector<unsigned char> master_key(AURA_Processor::KEY_SIZE, 0xCC);
    std::vector<unsigned char> payload = { 'd', 'a', 't', 'a' };

    const size_t width = 10, height = 10;
    std::vector<unsigned char> image_data(width * height * 4, 0xEE);
    AURA_ImageBuffer image_buffer { image_data.data(), width, height };

    AURA_Processor aura(master_key);
    aura.encrypt(payload, image_buffer);

    // flip a bit in the image data post-encryption
    image_data[20] ^= 0x01; // corrupt a byte within the data area

    std::vector<unsigned char> decrypted_payload;
    AURA_Result result = aura.decrypt(decrypted_payload, image_buffer);

    if (result != AURA_Result::Error_Authentication_Failed) {
        std::cerr << "    ERROR: Expected Error_Authentication_Failed, but got code " << static_cast<int>(result) << std::endl;
        return false;
    }
    return true;
}

// verifies that encryption fails if the image is too small
bool test_image_too_small_failure() {
    std::vector<unsigned char> master_key(AURA_Processor::KEY_SIZE, 0xDD);
    std::vector<unsigned char> payload(100, 'A');

    size_t required_pixels = AURA_Processor::calculate_required_pixels(payload.size());
    
    // create an image that is exactly one pixel too small
    size_t image_pixels = required_pixels - 1;
    std::vector<unsigned char> image_data(image_pixels * 4, 0xEE);
    AURA_ImageBuffer image_buffer { image_data.data(), image_pixels, 1 };

    AURA_Processor aura(master_key);
    AURA_Result result = aura.encrypt(payload, image_buffer);

    if (result != AURA_Result::Error_Image_Too_Small) {
        std::cerr << "    ERROR: Expected Error_Image_Too_Small, but got code " << static_cast<int>(result) << std::endl;
        return false;
    }
    return true;
}

// verifies that an empty payload is rejected
bool test_empty_payload_failure() {
    std::vector<unsigned char> master_key(AURA_Processor::KEY_SIZE, 0xFF);
    std::vector<unsigned char> payload; // empty payload

    const size_t width = 10, height = 10;
    std::vector<unsigned char> image_data(width * height * 4, 0xEE);
    AURA_ImageBuffer image_buffer { image_data.data(), width, height };

    AURA_Processor aura(master_key);
    AURA_Result result = aura.encrypt(payload, image_buffer);

    if (result != AURA_Result::Error_Invalid_Input) {
        std::cerr << "    ERROR: Expected Error_Invalid_Input for empty payload, but got code " << static_cast<int>(result) << std::endl;
        return false;
    }
    return true;
}


int main() {
    std::cout << "--- AURA Library Standalone Test Suite ---" << std::endl;
    std::cout << "============================================================" << std::endl;

    run_test("Standard Encrypt/Decrypt Cycle", test_happy_path);
    run_test("Failure with Incorrect Key", test_wrong_key_failure);
    run_test("Failure with Tampered Data", test_tampered_data_failure);
    run_test("Failure with Image Too Small", test_image_too_small_failure);
    run_test("Rejection of Empty Payload", test_empty_payload_failure);

    return 0;
}