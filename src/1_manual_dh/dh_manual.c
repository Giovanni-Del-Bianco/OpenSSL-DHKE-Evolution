#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h>

/*
 * ============================================================================
 * Function: handle_errors
 * ----------------------------------------------------------------------------
 * Prints OpenSSL errors to stderr and terminates the program.
 * This is a standard utility function used in OpenSSL-based programs.
 * ============================================================================
 */
void handle_errors() {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

/*
 * ============================================================================
 * Function: load_key
 * ----------------------------------------------------------------------------
 * Loads a key (private or public) from a PEM file.
 *
 * Parameters:
 *   - filename   : path to the PEM file
 *   - is_private : 1 if private key, 0 if public key
 *
 * Returns:
 *   - EVP_PKEY*  : pointer to the loaded key structure
 *
 * Notes:
 *   - Uses BIO abstraction for file handling (OpenSSL style)
 *   - Supports both private and public key formats
 * ============================================================================
 */
EVP_PKEY* load_key(const char* filename, int is_private) {
    BIO* bio = BIO_new_file(filename, "r");
    if (!bio) {
        fprintf(stderr, "Error: Unable to open file %s\n", filename);
        handle_errors();
    }

    EVP_PKEY* key = NULL;

    if (is_private) {
        key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    } else {
        key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    }

    BIO_free(bio);

    if (!key) {
        fprintf(stderr, "Error: Failed to load key from %s\n", filename);
        handle_errors();
    }

    return key;
}

/*
 * ============================================================================
 * Function: aes_128_cbc_crypt
 * ----------------------------------------------------------------------------
 * Performs AES-128-CBC encryption or decryption using OpenSSL EVP API.
 *
 * Parameters:
 *   - in        : input buffer (plaintext or ciphertext)
 *   - in_len    : length of input data
 *   - key       : AES key (128-bit used)
 *   - iv        : initialization vector (16 bytes)
 *   - out       : output buffer
 *   - encrypt   : 1 = encrypt, 0 = decrypt
 *
 * Returns:
 *   - out_len   : number of bytes written to output buffer
 *
 * Notes:
 *   - Uses EVP interface (recommended high-level API)
 *   - Automatically handles padding (PKCS#7)
 * ============================================================================
 */
int aes_128_cbc_crypt(unsigned char* in, int in_len,
                      unsigned char* key, unsigned char* iv,
                      unsigned char* out, int encrypt) {

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handle_errors();

    int len = 0;
    int out_len = 0;

    // Initialize cipher context (AES-128-CBC)
    if (EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv, encrypt) <= 0)
        handle_errors();

    // Process input data
    if (EVP_CipherUpdate(ctx, out, &len, in, in_len) <= 0)
        handle_errors();
    out_len = len;

    // Finalize operation (handles padding)
    if (EVP_CipherFinal_ex(ctx, out + len, &len) <= 0)
        handle_errors();
    out_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return out_len;
}

/*
 * ============================================================================
 * MAIN PROGRAM
 * ----------------------------------------------------------------------------
 * Implements a simplified Diffie-Hellman key exchange + AES encryption.
 *
 * Steps:
 *   1. Load keys (private + peer public)
 *   2. Derive shared secret using DH
 *   3. Hash the secret to obtain AES key
 *   4. Encrypt local plaintext file
 *   5. Decrypt received ciphertext
 * ============================================================================
 */
int main(int argc, char *argv[]) {

    /*
     * ------------------------------------------------------------------------
     * Argument check
     * ------------------------------------------------------------------------
     */
    if (argc < 3) {
        printf("Usage: %s <my_private.pem> <peer_public.pem>\n", argv[0]);
        return EXIT_FAILURE;
    }

    printf("[*] Loading keys...\n");

    /*
     * ------------------------------------------------------------------------
     * Step 1: Load keys
     * ------------------------------------------------------------------------
     */
    EVP_PKEY* my_priv = load_key(argv[1], 1);
    EVP_PKEY* peer_pub = load_key(argv[2], 0);

    printf("[+] Keys loaded successfully.\n");

    /*
     * ------------------------------------------------------------------------
     * Step 2: Derive shared secret (Diffie-Hellman)
     * ------------------------------------------------------------------------
     */
    printf("[*] Deriving shared secret...\n");

    EVP_PKEY_CTX* dctx = EVP_PKEY_CTX_new(my_priv, NULL);
    if (!dctx) handle_errors();

    if (EVP_PKEY_derive_init(dctx) <= 0)
        handle_errors();

    if (EVP_PKEY_derive_set_peer(dctx, peer_pub) <= 0)
        handle_errors();

    size_t secret_len;

    // First call: determine buffer size
    if (EVP_PKEY_derive(dctx, NULL, &secret_len) <= 0)
        handle_errors();

    unsigned char* secret = OPENSSL_malloc(secret_len);
    if (!secret) handle_errors();

    // Second call: actually derive the secret
    if (EVP_PKEY_derive(dctx, secret, &secret_len) <= 0)
        handle_errors();

    printf("[+] Shared secret derived (%zu bytes).\n", secret_len);

    /*
     * ------------------------------------------------------------------------
     * Step 3: Hash the secret to derive AES key
     * ------------------------------------------------------------------------
     */
    printf("[*] Deriving AES key from shared secret (SHA-256)...\n");

    unsigned char aes_key[32];  // 256-bit hash output
    SHA256(secret, secret_len, aes_key);

    printf("[+] AES key derived (using first 128 bits).\n");

    /*
     * ------------------------------------------------------------------------
     * Step 4: Encrypt local plaintext file
     * ------------------------------------------------------------------------
     */
    printf("[*] Encrypting local file: plain_text.txt...\n");

    unsigned char iv[] = "0123456789012345"; // 16-byte IV (static for lab ONLY)

    FILE* f_in = fopen("plain_text.txt", "rb");
    if (!f_in) {
        fprintf(stderr, "Error: Please create a file named 'plain_text.txt'\n");
        return EXIT_FAILURE;
    }

    unsigned char plaintext[1024];
    unsigned char ciphertext[1024];

    int p_len = fread(plaintext, 1, sizeof(plaintext), f_in);
    fclose(f_in);

    int c_len = aes_128_cbc_crypt(plaintext, p_len, aes_key, iv, ciphertext, 1);

    FILE* f_out = fopen("plain_text.enc", "wb");
    fwrite(ciphertext, 1, c_len, f_out);
    fclose(f_out);

    printf("[+] Encryption completed. Output file: plain_text.enc\n");

    /*
     * ------------------------------------------------------------------------
     * Step 5: Decrypt received ciphertext (simulation)
     * ------------------------------------------------------------------------
     */
    printf("[*] Decrypting ciphertext (simulation)...\n");

    unsigned char decrypted[1024];

    int d_len = aes_128_cbc_crypt(ciphertext, c_len, aes_key, iv, decrypted, 0);
    decrypted[d_len] = '\0';

    printf("[+] Decryption completed.\n");
    printf("[DECRYPTED MESSAGE]: %s\n", decrypted);

    /*
     * ------------------------------------------------------------------------
     * Cleanup
     * ------------------------------------------------------------------------
     */
    OPENSSL_free(secret);
    EVP_PKEY_free(my_priv);
    EVP_PKEY_free(peer_pub);
    EVP_PKEY_CTX_free(dctx);

    printf("[*] Resources cleaned up. Program finished successfully.\n");

    return EXIT_SUCCESS;
}