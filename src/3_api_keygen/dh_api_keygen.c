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
 * Centralized error handler for OpenSSL operations.
 * Prints the error stack and terminates the program.
 * ============================================================================
 */
void handle_errors() {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

/*
 * ============================================================================
 * Function: aes_128_cbc_crypt
 * ----------------------------------------------------------------------------
 * Performs AES-128-CBC encryption or decryption.
 *
 * Parameters:
 *   - in        : input buffer (plaintext or ciphertext)
 *   - in_len    : input length
 *   - key       : AES key (128-bit used)
 *   - iv        : initialization vector (16 bytes)
 *   - out       : output buffer
 *   - encrypt   : 1 = encrypt, 0 = decrypt
 *
 * Returns:
 *   - Number of bytes written to output buffer
 *
 * Notes:
 *   - Uses EVP high-level API
 *   - Handles padding automatically (PKCS#7)
 * ============================================================================
 */
int aes_128_cbc_crypt(unsigned char* in, int in_len,
                      unsigned char* key, unsigned char* iv,
                      unsigned char* out, int encrypt) {

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handle_errors();

    int len = 0;
    int out_len = 0;

    if (EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv, encrypt) <= 0)
        handle_errors();

    if (EVP_CipherUpdate(ctx, out, &len, in, in_len) <= 0)
        handle_errors();
    out_len = len;

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
 * Implements a full Diffie-Hellman workflow:
 *
 *   1. Load DH parameters from file
 *   2. Generate a fresh key pair
 *   3. Export public key for peer
 *   4. Wait for peer key exchange
 *   5. Derive shared secret
 *   6. Derive AES key using SHA-256
 *   7. Encrypt a local message
 *
 * This simulates an interleaved Alice/Bob protocol.
 * ============================================================================
 */
int main(int argc, char *argv[]) {

    /*
     * ------------------------------------------------------------------------
     * Argument validation
     * ------------------------------------------------------------------------
     */
    if (argc < 5) {
        printf("Usage: %s <params.pem> <my_pub_out.pem> <peer_pub_in.pem> <instance_name>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char* params_file   = argv[1];
    const char* my_pub_file   = argv[2];
    const char* peer_pub_file = argv[3];
    const char* instance_name = argv[4];

    printf("[%s] Starting DH protocol...\n", instance_name);

    /*
     * ------------------------------------------------------------------------
     * Step 1: Load DH parameters
     * ------------------------------------------------------------------------
     */
    BIO* b_params = BIO_new_file(params_file, "r");
    if (!b_params) {
        fprintf(stderr, "[%s] Error: Cannot open parameters file %s\n", instance_name, params_file);
        handle_errors();
    }

    EVP_PKEY* params = PEM_read_bio_Parameters(b_params, NULL);
    BIO_free(b_params);

    if (!params) {
        fprintf(stderr, "[%s] Error: Failed to load DH parameters\n", instance_name);
        handle_errors();
    }

    printf("[%s] DH parameters loaded from %s\n", instance_name, params_file);

    /*
     * ------------------------------------------------------------------------
     * Step 2: Generate DH key pair
     * ------------------------------------------------------------------------
     */
    EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new(params, NULL);
    if (!kctx) handle_errors();

    EVP_PKEY* my_key = NULL;

    if (EVP_PKEY_keygen_init(kctx) <= 0)
        handle_errors();

    if (EVP_PKEY_keygen(kctx, &my_key) <= 0)
        handle_errors();

    printf("[%s] DH key pair generated successfully\n", instance_name);

    /*
     * ------------------------------------------------------------------------
     * Step 3: Export public key
     * ------------------------------------------------------------------------
     */
    BIO* b_my_pub = BIO_new_file(my_pub_file, "w");
    if (!b_my_pub) handle_errors();

    if (!PEM_write_bio_PUBKEY(b_my_pub, my_key))
        handle_errors();

    BIO_free(b_my_pub);

    printf("[%s] Public key written to %s\n", instance_name, my_pub_file);
    printf("[%s] Exchange this file with your peer, then press ENTER to continue...\n", instance_name);

    getchar(); // Wait for manual exchange

    /*
     * ------------------------------------------------------------------------
     * Step 4: Load peer public key
     * ------------------------------------------------------------------------
     */
    BIO* b_peer_pub = BIO_new_file(peer_pub_file, "r");
    if (!b_peer_pub) {
        fprintf(stderr, "[%s] Error: Cannot open peer public key file %s\n", instance_name, peer_pub_file);
        handle_errors();
    }

    EVP_PKEY* peer_pub = PEM_read_bio_PUBKEY(b_peer_pub, NULL, NULL, NULL);
    BIO_free(b_peer_pub);

    if (!peer_pub) {
        fprintf(stderr, "[%s] Error: Failed to load peer public key\n", instance_name);
        handle_errors();
    }

    printf("[%s] Peer public key loaded successfully\n", instance_name);

    /*
     * ------------------------------------------------------------------------
     * Step 5: Derive shared secret (Diffie-Hellman)
     * ------------------------------------------------------------------------
     */
    printf("[%s] Deriving shared secret...\n", instance_name);

    EVP_PKEY_CTX* dctx = EVP_PKEY_CTX_new(my_key, NULL);
    if (!dctx) handle_errors();

    if (EVP_PKEY_derive_init(dctx) <= 0)
        handle_errors();

    if (EVP_PKEY_derive_set_peer(dctx, peer_pub) <= 0)
        handle_errors();

    size_t secret_len;

    if (EVP_PKEY_derive(dctx, NULL, &secret_len) <= 0)
        handle_errors();

    unsigned char* secret = OPENSSL_malloc(secret_len);
    if (!secret) handle_errors();

    if (EVP_PKEY_derive(dctx, secret, &secret_len) <= 0)
        handle_errors();

    printf("[%s] Shared secret derived (%zu bytes)\n", instance_name, secret_len);

    /*
     * ------------------------------------------------------------------------
     * Step 6: Derive AES key from shared secret
     * ------------------------------------------------------------------------
     */
    printf("[%s] Deriving AES key using SHA-256...\n", instance_name);

    unsigned char aes_key[32];
    SHA256(secret, secret_len, aes_key);

    printf("[%s] AES key ready (128-bit will be used)\n", instance_name);

    /*
     * ------------------------------------------------------------------------
     * Step 7: Encrypt local message
     * ------------------------------------------------------------------------
     */
    unsigned char iv[] = "0123456789012345"; // STATIC IV (lab only)

    char plaintext_file[64];
    char ciphertext_file[64];

    snprintf(plaintext_file, sizeof(plaintext_file), "%s_plain.txt", instance_name);
    snprintf(ciphertext_file, sizeof(ciphertext_file), "%s_cipher.enc", instance_name);

    // Create a test message
    FILE* f_p = fopen(plaintext_file, "w");
    fprintf(f_p, "Secret message from %s", instance_name);
    fclose(f_p);

    printf("[%s] Created plaintext file: %s\n", instance_name, plaintext_file);

    unsigned char plaintext[1024];
    unsigned char ciphertext[1024];

    FILE* f_in = fopen(plaintext_file, "rb");
    int p_len = fread(plaintext, 1, sizeof(plaintext), f_in);
    fclose(f_in);

    int c_len = aes_128_cbc_crypt(plaintext, p_len, aes_key, iv, ciphertext, 1);

    FILE* f_out = fopen(ciphertext_file, "wb");
    fwrite(ciphertext, 1, c_len, f_out);
    fclose(f_out);

    printf("[%s] Encryption complete → Output file: %s\n", instance_name, ciphertext_file);

    /*
     * ------------------------------------------------------------------------
     * Cleanup
     * ------------------------------------------------------------------------
     */
    OPENSSL_free(secret);
    EVP_PKEY_free(params);
    EVP_PKEY_free(my_key);
    EVP_PKEY_free(peer_pub);
    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_CTX_free(dctx);

    printf("[%s] Cleanup complete. Protocol finished successfully.\n", instance_name);

    return EXIT_SUCCESS;
}