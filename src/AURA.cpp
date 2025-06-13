#include "AURA.h"
#include <memory>
#include <botan/kdf.h>
#include <botan/stream_cipher.h>
#include <botan/mac.h>
#include <botan/exceptn.h>
#include <botan/mem_ops.h>
#include <botan/hex.h>
#include <algorithm>
#include <numeric>
#include <cstring>

namespace {

    // embeds a single byte into the least significant two bits of four color channels (RGBA)
    void embed_byte_in_pixel(unsigned char byte, unsigned char* pixel_ptr) {
        pixel_ptr[0] = (pixel_ptr[0] & 0xFC) | ((byte >> 6) & 0x03);
        pixel_ptr[1] = (pixel_ptr[1] & 0xFC) | ((byte >> 4) & 0x03);
        pixel_ptr[2] = (pixel_ptr[2] & 0xFC) | ((byte >> 2) & 0x03);
        pixel_ptr[3] = (pixel_ptr[3] & 0xFC) | ((byte >> 0) & 0x03);
    }

    // extracts a single byte from the least significant two bits of four color channels (RGBA)
    unsigned char extract_byte_from_pixel(const unsigned char* pixel_ptr) {
        unsigned char byte = 0;
        byte |= (pixel_ptr[0] & 0x03) << 6;
        byte |= (pixel_ptr[1] & 0x03) << 4;
        byte |= (pixel_ptr[2] & 0x03) << 2;
        byte |= (pixel_ptr[3] & 0x03) << 0;
        return byte;
    }

    // generates associated data for HMAC, combining pixel coordinates and cleaned pixel data
    std::vector<unsigned char> get_associated_data(const unsigned char* pixel_ptr, size_t x, size_t y) {
        std::vector<unsigned char> ad;
        ad.reserve(sizeof(x) + sizeof(y) + 4);
        ad.insert(ad.end(), reinterpret_cast<const unsigned char*>(&x), reinterpret_cast<const unsigned char*>(&x) + sizeof(x));
        ad.insert(ad.end(), reinterpret_cast<const unsigned char*>(&y), reinterpret_cast<const unsigned char*>(&y) + sizeof(y));
        ad.push_back(pixel_ptr[0] & 0xFC);
        ad.push_back(pixel_ptr[1] & 0xFC);
        ad.push_back(pixel_ptr[2] & 0xFC);
        ad.push_back(pixel_ptr[3] & 0xFC);
        return ad;
    }
}

// AURA_Processor constructor, initializes with master key
AURA_Processor::AURA_Processor(const std::vector<unsigned char>& master_key) {
    master_key_ = master_key;

    // derive keys if master key size is correct
    if (master_key_.size() == KEY_SIZE) {
        _deriveKeys();
    }
}

// derives encryption, pixel selection, and authentication keys using HKDF-SHA512
void AURA_Processor::_deriveKeys() {
    std::unique_ptr<Botan::KDF> kdf(Botan::get_kdf("HKDF(SHA-512)"));
    const std::string salt_str = "AURA-KEY-DERIVATION-V1";
    std::vector<uint8_t> salt(salt_str.begin(), salt_str.end());

    // derive combined key material
    auto ikm = kdf->derive_key(KEY_SIZE * 3, master_key_, salt, std::vector<uint8_t>());

    // assign key parts
    encryption_key_.assign(ikm.begin(), ikm.begin() + KEY_SIZE);
    pixel_selection_key_.assign(ikm.begin() + KEY_SIZE, ikm.begin() + KEY_SIZE * 2);
    authentication_key_.assign(ikm.begin() + KEY_SIZE * 2, ikm.end());
}

// generates a cryptographically secure random permutation of pixel indices
std::vector<size_t> AURA_Processor::_generatePixelPath(size_t total_pixels) const {
    std::unique_ptr<Botan::StreamCipher> csp_rng(Botan::StreamCipher::create("ChaCha20"));
    csp_rng->set_key(pixel_selection_key_.data(), pixel_selection_key_.size());
    
    std::vector<size_t> path(total_pixels);
    std::iota(path.begin(), path.end(), 0);
    
    // Fisher-Yates shuffle using CSPRNG
    for (size_t i = path.size() - 1; i > 0; --i) {
        std::vector<uint8_t> buf(sizeof(size_t));
        csp_rng->cipher(buf.data(), buf.data(), buf.size());
        size_t j_raw;
        std::memcpy(&j_raw, buf.data(), sizeof(size_t));
        std::swap(path[i], path[j_raw % (i + 1)]);
    }
    return path;
}

// calculate required pixels for a given payload size
size_t AURA_Processor::calculate_required_pixels(size_t payload_size) {
    if (payload_size == 0) {
        return 0;
    }

    // embeds one byte per pixel and requires space for the payload
    // plus a fixed-size authentication tag.
    return payload_size + AUTH_TAG_SIZE;
}

// encrypts payload and embeds it into the image using steganography
AURA_Result AURA_Processor::encrypt(const std::vector<unsigned char>& payload, AURA_ImageBuffer& image) {
    // validate input
    if (master_key_.size() != KEY_SIZE) {
        return AURA_Result::Error_Invalid_Input;
    }

    if (!image.pixel_data || payload.empty()) {
        return AURA_Result::Error_Invalid_Input;
    }

    const size_t total_pixels = image.width * image.height;
    const size_t required_pixels = payload.size() + AUTH_TAG_SIZE;

    // check if image is large enough
    if (total_pixels < required_pixels) {
        return AURA_Result::Error_Image_Too_Small;
    }

    try {
        auto pixel_path = _generatePixelPath(total_pixels);
        std::unique_ptr<Botan::StreamCipher> cipher(Botan::StreamCipher::create("ChaCha20"));
        cipher->set_key(encryption_key_.data(), encryption_key_.size());

        std::unique_ptr<Botan::MessageAuthenticationCode> hmac(Botan::MessageAuthenticationCode::create("HMAC(SHA-512)"));
        hmac->set_key(authentication_key_.data(), authentication_key_.size());

        // encrypt and embed payload bytes
        for (size_t i = 0; i < payload.size(); ++i) {
            size_t pixel_index = pixel_path[i];
            unsigned char* pixel_ptr = image.pixel_data + (pixel_index * 4);
            size_t x = pixel_index % image.width;
            size_t y = pixel_index / image.width;

            unsigned char encrypted_byte = payload[i];
            cipher->cipher1(&encrypted_byte, 1);
            
            // update HMAC with associated data and encrypted byte
            auto ad = get_associated_data(pixel_ptr, x, y);
            hmac->update(ad.data(), ad.size());
            hmac->update(&encrypted_byte, 1);
            
            embed_byte_in_pixel(encrypted_byte, pixel_ptr);
        }

        // calculate and embed authentication tag
        auto auth_tag = hmac->final();
        for (size_t i = 0; i < AUTH_TAG_SIZE; ++i) {
            size_t pixel_index = pixel_path[payload.size() + i];
            unsigned char* pixel_ptr = image.pixel_data + (pixel_index * 4);
            embed_byte_in_pixel(auth_tag[i], pixel_ptr);
        }

    } catch (const Botan::Exception&) {
        return AURA_Result::Error_Crypto_Error;
    }
    
    return AURA_Result::Success;
}

// decrypts and extracts payload from the image
AURA_Result AURA_Processor::decrypt(std::vector<unsigned char>& payload_out, const AURA_ImageBuffer& image) {
    payload_out.clear();

    // validate input
    if (master_key_.size() != KEY_SIZE) { 
        return AURA_Result::Error_Invalid_Input;
    }

    if (!image.pixel_data) {
        return AURA_Result::Error_Invalid_Input;
    }

    const size_t total_pixels = image.width * image.height;
    
    // check if image contains enough data for authentication tag
    if (total_pixels <= AUTH_TAG_SIZE) {
        return AURA_Result::Error_Image_Too_Small;
    }

    try {
        auto pixel_path = _generatePixelPath(total_pixels);
        std::unique_ptr<Botan::StreamCipher> cipher(Botan::StreamCipher::create("ChaCha20"));
        cipher->set_key(encryption_key_.data(), encryption_key_.size());
        
        // extract encrypted header to determine payload length
        std::vector<uint8_t> encrypted_header(sizeof(uint64_t));
        for(size_t i = 0; i < sizeof(uint64_t); ++i) {
            size_t pixel_index = pixel_path[i];
            const unsigned char* pixel_ptr = image.pixel_data + (pixel_index * 4);
            encrypted_header[i] = extract_byte_from_pixel(pixel_ptr);
        }
        
        // decrypt header
        std::vector<uint8_t> decrypted_header = encrypted_header;
        cipher->cipher(encrypted_header.data(), decrypted_header.data(), decrypted_header.size());
        
        uint64_t payload_length_from_header;
        std::memcpy(&payload_length_from_header, decrypted_header.data(), sizeof(uint64_t));

        // validate extracted payload length
        if (payload_length_from_header == 0 || payload_length_from_header > total_pixels - AUTH_TAG_SIZE) {
            return AURA_Result::Error_Authentication_Failed;
        }

        std::unique_ptr<Botan::MessageAuthenticationCode> hmac(Botan::MessageAuthenticationCode::create("HMAC(SHA-512)"));
        hmac->set_key(authentication_key_.data(), authentication_key_.size());

        std::vector<unsigned char> extracted_encrypted_payload(payload_length_from_header);
        
        // extract encrypted payload and update HMAC
        for (size_t i = 0; i < payload_length_from_header; ++i) {
            size_t pixel_index = pixel_path[i];
            const unsigned char* pixel_ptr = image.pixel_data + (pixel_index * 4);
            size_t x = pixel_index % image.width;
            size_t y = pixel_index / image.width;

            extracted_encrypted_payload[i] = extract_byte_from_pixel(pixel_ptr);
            auto ad = get_associated_data(pixel_ptr, x, y);
            hmac->update(ad.data(), ad.size());
            hmac->update(&extracted_encrypted_payload[i], 1);
        }
        
        // extract authentication tag
        std::vector<unsigned char> extracted_tag(AUTH_TAG_SIZE);
        for (size_t i = 0; i < AUTH_TAG_SIZE; ++i) {
            size_t pixel_index = pixel_path[payload_length_from_header + i];
            const unsigned char* pixel_ptr = image.pixel_data + (pixel_index * 4);
            extracted_tag[i] = extract_byte_from_pixel(pixel_ptr);
        }

        // verify authentication tag
        if (!hmac->verify_mac(extracted_tag.data(), extracted_tag.size())) {
            return AURA_Result::Error_Authentication_Failed;
        }

        cipher->seek(0); // reset cipher state
        payload_out.resize(payload_length_from_header);

        // decrypt extracted payload
        cipher->cipher(extracted_encrypted_payload.data(), payload_out.data(), payload_length_from_header);

    } catch (const Botan::Exception&) {
        payload_out.clear();
        return AURA_Result::Error_Crypto_Error;
    }

    return AURA_Result::Success;
}