#ifndef AURA_H
#define AURA_H

#include <vector>
#include <cstddef>

// defines the result codes for AURA operations
enum class AURA_Result {
    Success,
    Error_Image_Too_Small,
    Error_Authentication_Failed,
    Error_Invalid_Input,
    Error_Crypto_Error
};

// represents the image buffer passed to AURA
struct AURA_ImageBuffer {
    unsigned char* pixel_data;
    size_t width;
    size_t height;
};

// provides the core AURA steganography implementation
class AURA_Processor {
public:
    static const size_t KEY_SIZE = 32;
    static const size_t AUTH_TAG_SIZE = 64;
    static const size_t IV_SIZE = 12;

    AURA_Processor(const std::vector<unsigned char>& master_key);

    AURA_Result encrypt(const std::vector<unsigned char>& payload, AURA_ImageBuffer& image);
    AURA_Result decrypt(std::vector<unsigned char>& payload_out, const AURA_ImageBuffer& image);

    static size_t calculate_required_pixels(size_t payload_size);

private:
    std::vector<unsigned char> master_key_;
    std::vector<unsigned char> encryption_key_;
    std::vector<unsigned char> pixel_selection_key_;
    std::vector<unsigned char> authentication_key_;

    void _deriveKeys();
    std::vector<size_t> _generatePixelPath(size_t total_pixels) const;
};

#endif