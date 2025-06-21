#include "AURA.h"
#include <memory>
#include <botan/kdf.h>
#include <botan/stream_cipher.h>
#include <botan/mac.h>
#include <botan/exceptn.h>
#include <botan/mem_ops.h>
#include <botan/hex.h>
#include <botan/system_rng.h>
#include <botan/secmem.h>
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
    std::vector<uint8_t> iv(IV_SIZE, 0);
    csp_rng->set_iv(iv.data(), iv.size());

    std::vector<size_t> path(total_pixels);
    std::iota(path.begin(), path.end(), 0);

    // Fisher-Yates shuffle using CSPRNG
    for (size_t i = path.size() - 1; i > 0; --i) {
        std::vector<uint8_t> buf(sizeof(size_t), 0);
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

    // embeds one byte per pixel and requires space for the IV, the payload,
    // and a fixed-size authentication tag.
    return IV_SIZE + payload_size + AUTH_TAG_SIZE;
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
    const size_t required_pixels = IV_SIZE + payload.size() + AUTH_TAG_SIZE;

    // check if image is large enough
    if (total_pixels < required_pixels) {
        return AURA_Result::Error_Image_Too_Small;
    }

    try {
        auto pixel_path = _generatePixelPath(total_pixels);
        std::unique_ptr<Botan::StreamCipher> cipher(Botan::StreamCipher::create("ChaCha20"));
        cipher->set_key(encryption_key_.data(), encryption_key_.size());
        
        Botan::secure_vector<uint8_t> iv(IV_SIZE);
        Botan::system_rng().randomize(iv.data(), iv.size());
        cipher->set_iv(iv.data(), iv.size());

        std::vector<unsigned char> encrypted_payload = payload;
        cipher->cipher(encrypted_payload.data(), encrypted_payload.data(), encrypted_payload.size());

        std::vector<unsigned char> data_to_embed;
        data_to_embed.insert(data_to_embed.end(), iv.begin(), iv.end());
        data_to_embed.insert(data_to_embed.end(), encrypted_payload.begin(), encrypted_payload.end());

        std::unique_ptr<Botan::MessageAuthenticationCode> hmac(Botan::MessageAuthenticationCode::create("HMAC(SHA-512)"));
        hmac->set_key(authentication_key_.data(), authentication_key_.size());

        // embed authenticated data (IV + ciphertext)
        for (size_t i = 0; i < data_to_embed.size(); ++i) {
            size_t pixel_index = pixel_path[i];
            unsigned char* pixel_ptr = image.pixel_data + (pixel_index * 4);
            size_t x = pixel_index % image.width;
            size_t y = pixel_index / image.width;

            // update HMAC with associated data and embedded byte
            auto ad = get_associated_data(pixel_ptr, x, y);
            hmac->update(ad.data(), ad.size());
            hmac->update(&data_to_embed[i], 1);

            embed_byte_in_pixel(data_to_embed[i], pixel_ptr);
        }

        // calculate and embed authentication tag
        auto auth_tag = hmac->final();
        for (size_t i = 0; i < AUTH_TAG_SIZE; ++i) {
            size_t pixel_index = pixel_path[data_to_embed.size() + i];
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

    // check if image can contain at least the minimum required data
    if (total_pixels <= (IV_SIZE + AUTH_TAG_SIZE)) {
        return AURA_Result::Error_Image_Too_Small;
    }

    try {
        // generate the deterministic pixel sequence
        auto pixel_path = _generatePixelPath(total_pixels);

        // extract the initialization vector from the start of the pixel path
        std::vector<uint8_t> iv(IV_SIZE);
        for(size_t i = 0; i < IV_SIZE; ++i) {
            size_t pixel_index = pixel_path[i];
            const unsigned char* pixel_ptr = image.pixel_data + (pixel_index * 4);
            iv[i] = extract_byte_from_pixel(pixel_ptr);
        }

        // create a cipher to decrypt only the payload's length header
        std::unique_ptr<Botan::StreamCipher> header_cipher(Botan::StreamCipher::create("ChaCha20"));
        header_cipher->set_key(encryption_key_.data(), encryption_key_.size());
        header_cipher->set_iv(iv.data(), iv.size());

        // extract and decrypt the header to determine payload length
        std::vector<uint8_t> encrypted_header(sizeof(uint64_t));
        for(size_t i = 0; i < sizeof(uint64_t); ++i) {
            size_t pixel_index = pixel_path[IV_SIZE + i];
            const unsigned char* pixel_ptr = image.pixel_data + (pixel_index * 4);
            encrypted_header[i] = extract_byte_from_pixel(pixel_ptr);
        }
        header_cipher->cipher(encrypted_header.data(), encrypted_header.data(), encrypted_header.size());

        // reconstruct the 64-bit length from the decrypted header bytes
        uint64_t payload_length_from_header = 0;
        for(size_t i = 0; i < sizeof(uint64_t); ++i) {
            payload_length_from_header = (payload_length_from_header << 8) | encrypted_header[i];
        }
        
        // critical sanity check to mitigate dos attacks
        if (payload_length_from_header == 0 || (IV_SIZE + payload_length_from_header + AUTH_TAG_SIZE) > total_pixels) {
            return AURA_Result::Error_Authentication_Failed;
        }

        const size_t total_embedded_data_size = IV_SIZE + payload_length_from_header;
        std::vector<unsigned char> extracted_embedded_data(total_embedded_data_size);
        std::unique_ptr<Botan::MessageAuthenticationCode> hmac(Botan::MessageAuthenticationCode::create("HMAC(SHA-512)"));
        hmac->set_key(authentication_key_.data(), authentication_key_.size());

        // now extract all embedded data (iv + ciphertext) and update hmac
        for (size_t i = 0; i < total_embedded_data_size; ++i) {
            size_t pixel_index = pixel_path[i];
            const unsigned char* pixel_ptr = image.pixel_data + (pixel_index * 4);
            size_t x = pixel_index % image.width;
            size_t y = pixel_index / image.width;

            extracted_embedded_data[i] = extract_byte_from_pixel(pixel_ptr);

            auto ad = get_associated_data(pixel_ptr, x, y);
            hmac->update(ad.data(), ad.size());
            hmac->update(&extracted_embedded_data[i], 1);
        }

        // extract authentication tag
        std::vector<unsigned char> extracted_tag(AUTH_TAG_SIZE);
        for (size_t i = 0; i < AUTH_TAG_SIZE; ++i) {
            size_t pixel_index = pixel_path[total_embedded_data_size + i];
            const unsigned char* pixel_ptr = image.pixel_data + (pixel_index * 4);
            extracted_tag[i] = extract_byte_from_pixel(pixel_ptr);
        }

        // verify authentication tag
        if (!hmac->verify_mac(extracted_tag.data(), extracted_tag.size())) {
            return AURA_Result::Error_Authentication_Failed;
        }
        
        // if authentication succeeds, assign the now-verified payload
        const unsigned char* ciphertext = extracted_embedded_data.data() + IV_SIZE;
        payload_out.resize(payload_length_from_header);

        std::unique_ptr<Botan::StreamCipher> final_cipher(Botan::StreamCipher::create("ChaCha20"));
        final_cipher->set_key(encryption_key_.data(), encryption_key_.size());
        final_cipher->set_iv(iv.data(), iv.size());
        final_cipher->cipher(ciphertext, payload_out.data(), payload_length_from_header);

    } catch (const Botan::Exception&) {
        payload_out.clear();
        return AURA_Result::Error_Crypto_Error;
    }

    return AURA_Result::Success;
}