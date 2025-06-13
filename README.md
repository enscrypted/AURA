# AURA (Authenticated Unified Raster Algorithm) Library

AURA is a standalone C++17 library designed for high-security, authenticated steganography. It is a core component of the `cZip` v2.0 project and is designed to be included as a submodule.

This document provides an overview of the library, its security model, and instructions for building and using it.

### Design Philosophy & Security Guarantees

#### A Secure Protocol, Not a New Algorithm

It is important to understand that AURA is a **cryptographic protocol**, not a new encryption algorithm. A protocol is a defined set of rules that uses existing, trusted algorithms to achieve a security goal. AURA's security is built upon a foundation of industry-standard cryptographic primitives; it does not "roll its own crypto." This is a fundamental design decision that ensures robustness and avoids the pitfalls of unvetted custom algorithms.

#### The Cover-Binding Advantage: Authenticated Encryption

AURA's primary security feature is its implementation of an **AEAD (Authenticated Encryption with Associated Data)** scheme.

In a typical "encrypt-then-hide" workflow, the encrypted data is a self-contained blob. It can be extracted from one image and re-embedded into a different image without invalidating the encryption. This opens it up to "replay" or "source tampering" attacks, where an attacker can move your secret message to a different context.

AURA prevents this by making the authentication tag a fingerprint of both the secret message **and the cover image itself**. It achieves this by using the image pixels' metadata (coordinates and color data) as "Associated Data" during the HMAC authentication process.

**This provides a critical security guarantee:** An AURA payload is cryptographically bound to the image it was created in. If an attacker copies the payload to a different image, the authentication check will fail upon decryption.

### Core Cryptographic Features

* **Confidentiality:** Provided by the **ChaCha20** stream cipher.
* **Integrity & Authenticity:** Provided by **HMAC-SHA512**.
* **Key Derivation:** A single master key is securely expanded into independent keys for each cryptographic task using **HKDF-SHA512**.
* **Steganographic Security:** A secret, non-sequential pixel path is generated using a **ChaCha20-based CSPRNG** to prevent trivial data extraction and analysis.

### Building the Library

The AURA library is built with CMake.

1.  **Clone the Repository:**
    Ensure you clone with the `--recurse-submodules` flag to fetch the Botan dependency.
    ```sh
    git clone --recurse-submodules <your-repo-url>
    ```
2.  **Configure and Build:**
    ```sh
    # From the root AURA directory
    cmake -B build
    cmake --build build
    ```
    The compiled libraries will be located in the `build/` directory, and the test harness will be in `build/test/`.

### API Usage Example

The AURA API includes a static helper function, `calculate_required_pixels()`, to determine the required image size for a given payload. This is useful for pre-flight checks to validate a cover image before attempting to embed data.

```cpp
#include "AURA.h"
#include <vector>
#include <iostream>

int main() {
    // 1. Prepare data
    std::vector<unsigned char> master_key(AURA_Processor::KEY_SIZE, 0xAA);
    std::vector<unsigned char> my_data = { 's', 'e', 'c', 'r', 'e', 't' };
    
    // 2. Perform pre-flight size check
    size_t required_pixels = AURA_Processor::calculate_required_pixels(my_data.size());
    std::cout << "Payload of size " << my_data.size() << " requires " << required_pixels << " pixels." << std::endl;
    
    // In a real app, create or load an image
    const size_t image_width = 100;
    const size_t image_height = 100;
    if (image_width * image_height < required_pixels) {
        std::cerr << "Error: Image is too small." << std::endl;
        return 1;
    }
    
    std::vector<unsigned char> image_pixel_data(image_width * image_height * 4, 0xFF);
    AURA_ImageBuffer image_buffer { image_pixel_data.data(), image_width, image_height };

    // 3. Encrypt
    AURA_Processor aura(master_key);
    AURA_Result result = aura.encrypt(my_data, image_buffer);

    // 4. Decrypt and verify
    if (result == AURA_Result::Success) {
        std::vector<unsigned char> decrypted_data;
        result = aura.decrypt(decrypted_data, image_buffer);
        if (result == AURA_Result::Success && decrypted_data == my_data) {
            // Success!
            std::cout << "SUCCESS: Round-trip successful." << std::endl;
        }
    }
    return 0;
}
```

### License

The AURA library is free software distributed under the terms of the GNU Lesser General Public License.