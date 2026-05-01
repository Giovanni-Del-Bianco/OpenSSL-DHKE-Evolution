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
 * Centralized OpenSSL error handler.
 * Prints the OpenSSL error stack and terminates execution.
 * ============================================================================
 */
void handle_errors() {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

/*
 * ============================================================================
 * Function: load_ec_key
 * ----------------------------------------------------------------------------
 * Loads an Elliptic Curve (EC) key from a PEM file.
 *
 * Parameters:
 *   - filename   : path to the PEM file
 *   - is_private : 1 for private key, 0 for public key
 *
 * Returns:
 *   - EVP_PKEY*  : pointer to the loaded key
 *
 * Notes:
 *   - Uses BIO interface (OpenSSL abstraction for I/O)
 *   - PEM_read_bio_PrivateKey → loads private keys
 *   - PEM_read_bio_PUBKEY     → loads public keys
 * ============================================================================
 */
EVP_PKEY* load_ec_key(const char* filename, int is_private) {
    BIO* bio = BIO_new_file(filename, "r");
    if (!bio) {
        fprintf(stderr, "Error: Cannot open file %s\n", filename);
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
 *   - in_len    : length of input
 *   - key       : AES key (first 128 bits used)
 *   - iv        : initialization vector (16 bytes)
 *   - out       : output buffer
 *   - encrypt   : 1 = encrypt, 0 = decrypt
 *
 * Returns:
 *   - out_len   : number of bytes written to output
 *
 * Notes:
 *   - Uses high-level EVP API (recommended)
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

    // Initialize AES-128-CBC operation
    if (EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv, encrypt) <= 0)
        handle_errors();

    // Process input data
    if (EVP_CipherUpdate(ctx, out, &len, in, in_len) <= 0)
        handle_errors();
    out_len = len;

    // Finalize (handles padding)
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
 * Implements ECDH key exchange + AES encryption.
 *
 * Steps:
 *   1. Load EC keys (private + peer public)
 *   2. Derive shared secret using ECDH
 *   3. Hash the secret (SHA-256) to derive AES key
 *   4. Encrypt local file
 *   5. Decrypt ciphertext (verification)
 * ============================================================================
 */
int main(int argc, char *argv[]) {

    /*
     * ------------------------------------------------------------------------
     * Argument validation
     * ------------------------------------------------------------------------
     */
    if (argc < 3) {
        printf("Usage: %s <my_private_EC.pem> <peer_public_EC.pem>\n", argv[0]);
        return EXIT_FAILURE;
    }

    printf("[*] Loading EC keys...\n");

    /*
     * ------------------------------------------------------------------------
     * Step 1: Load keys
     * ------------------------------------------------------------------------
     */
    EVP_PKEY* my_priv = load_ec_key(argv[1], 1);
    EVP_PKEY* peer_pub = load_ec_key(argv[2], 0);

    printf("[+] EC keys loaded successfully.\n");

    /*
     * ------------------------------------------------------------------------
     * Step 2: Derive shared secret (ECDH)
     * ------------------------------------------------------------------------
     */
    printf("[*] Deriving shared secret using ECDH...\n");

    EVP_PKEY_CTX* dctx = EVP_PKEY_CTX_new(my_priv, NULL);
    if (!dctx) handle_errors();

    if (EVP_PKEY_derive_init(dctx) <= 0)
        handle_errors();

    // Set peer public key (point on the curve)
    if (EVP_PKEY_derive_set_peer(dctx, peer_pub) <= 0)
        handle_errors();

    size_t secret_len;

    // First call: get required buffer size
    if (EVP_PKEY_derive(dctx, NULL, &secret_len) <= 0)
        handle_errors();

    unsigned char* secret = OPENSSL_malloc(secret_len);
    if (!secret) handle_errors();

    // Second call: derive the shared secret
    if (EVP_PKEY_derive(dctx, secret, &secret_len) <= 0)
        handle_errors();

    printf("[+] Shared secret derived (%zu bytes).\n", secret_len);

    /*
     * ------------------------------------------------------------------------
     * Step 3: Derive AES key using SHA-256
     * ------------------------------------------------------------------------
     */
    printf("[*] Deriving AES key from shared secret (SHA-256)...\n");

    unsigned char aes_key[32]; // SHA-256 output
    SHA256(secret, secret_len, aes_key);

    printf("[+] AES key ready (first 128 bits will be used).\n");

    /*
     * ------------------------------------------------------------------------
     * Step 4: Encrypt plaintext file
     * ------------------------------------------------------------------------
     */
    printf("[*] Encrypting file: plain_text.txt...\n");

    // Static IV (ONLY for lab/testing purposes)
    unsigned char iv[] = "abcdef0123456789";

    FILE* f_in = fopen("plain_text.txt", "rb");
    if (!f_in) {
        fprintf(stderr, "Error: Please create 'plain_text.txt'\n");
        return EXIT_FAILURE;
    }

    unsigned char plaintext[2048];
    unsigned char ciphertext[2048];

    int p_len = fread(plaintext, 1, sizeof(plaintext), f_in);
    fclose(f_in);

    int c_len = aes_128_cbc_crypt(plaintext, p_len, aes_key, iv, ciphertext, 1);

    FILE* f_out = fopen("plain_text.enc", "wb");
    fwrite(ciphertext, 1, c_len, f_out);
    fclose(f_out);

    printf("[+] Encryption completed → Output: plain_text.enc\n");

    /*
     * ------------------------------------------------------------------------
     * Step 5: Decryption (verification)
     * ------------------------------------------------------------------------
     */
    printf("[*] Decrypting ciphertext (verification step)...\n");

    unsigned char decrypted[2048];

    int d_len = aes_128_cbc_crypt(ciphertext, c_len, aes_key, iv, decrypted, 0);
    decrypted[d_len] = '\0';

    printf("[+] Decryption successful.\n");
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

    printf("[*] Resources freed. Program terminated successfully.\n");

    return EXIT_SUCCESS;
}