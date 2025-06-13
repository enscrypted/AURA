#ifndef AURA_H
#define AURA_H

#include <vector>
#include <string>

// C-style struct to pass raw image data to/from the library
struct AURA_ImageBuffer {
    unsigned char* pixel_data; // raw RGBA8888 pixel data
    size_t width;
    size_t height;
};

// result enum for clear error handling
enum class AURA_Result {
    Success,
    Error_Authentication_Failed,
    Error_Image_Too_Small,
    Error_Invalid_Input,
    Error_Crypto_Error
};

class AURA_Processor {
public:
    static constexpr size_t KEY_SIZE = 32; // 256 bits
    static constexpr size_t AUTH_TAG_SIZE = 64; // 512 bits for HMAC-SHA512

    AURA_Processor(const std::vector<unsigned char>& master_key);

    // calculate required pixels for a given payload size
    static size_t calculate_required_pixels(size_t payload_size);

    // encrypts payload and embeds it into the image
    AURA_Result encrypt(const std::vector<unsigned char>& payload, AURA_ImageBuffer& image);

    // extracts and decrypts the payload from an image
    AURA_Result decrypt(std::vector<unsigned char>& payload_out, const AURA_ImageBuffer& image);

private:
    void _deriveKeys();
    std::vector<size_t> _generatePixelPath(size_t total_pixels) const;

    // member keys
    std::vector<unsigned char> master_key_;
    std::vector<unsigned char> encryption_key_;
    std::vector<unsigned char> pixel_selection_key_;
    std::vector<unsigned char> authentication_key_;
};

#endif