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
 * Function: aes_128_cbc_crypt
 * ----------------------------------------------------------------------------
 * Performs AES-128-CBC encryption or decryption.
 *
 * Parameters:
 *   - in        : input buffer (plaintext or ciphertext)
 *   - in_len    : input length
 *   - key       : AES key (first 128 bits used)
 *   - iv        : initialization vector (16 bytes)
 *   - out       : output buffer
 *   - encrypt   : 1 = encrypt, 0 = decrypt
 *
 * Returns:
 *   - Number of bytes written to output buffer
 *
 * Notes:
 *   - Uses EVP high-level API
 *   - Handles PKCS#7 padding automatically
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
 * Full Diffie-Hellman protocol using OpenSSL API (no external parameters file):
 *
 *   PHASE 1: Generate DH parameters (ffdhe2048 group)
 *   PHASE 2: Generate key pair
 *   PHASE 3: Exchange public keys
 *   PHASE 4: Derive shared secret
 *   PHASE 5: Derive AES key (SHA-256)
 *   PHASE 6: Encrypt local message
 *   PHASE 7: Decrypt peer message
 *
 * This simulates a real Alice/Bob interleaved protocol.
 * ============================================================================
 */
int main(int argc, char *argv[]) {

    /*
     * ------------------------------------------------------------------------
     * Argument validation
     * ------------------------------------------------------------------------
     */
    if (argc < 3) {
        printf("Usage: %s <my_id> <peer_id>\n", argv[0]);
        printf("Example: ./dh_full Alice Bob\n");
        return EXIT_FAILURE;
    }

    char *my_id   = argv[1];
    char *peer_id = argv[2];

    char my_pub_name[64];
    char peer_pub_name[64];
    char peer_enc_name[64];

    snprintf(my_pub_name, sizeof(my_pub_name), "%s_pub.pem", my_id);
    snprintf(peer_pub_name, sizeof(peer_pub_name), "%s_pub.pem", peer_id);
    snprintf(peer_enc_name, sizeof(peer_enc_name), "%s_cipher.enc", peer_id);

    printf("[%s] Starting DH protocol using OpenSSL API...\n", my_id);

    /*
     * ------------------------------------------------------------------------
     * PHASE 1: Generate DH parameters (ffdhe2048)
     * ------------------------------------------------------------------------
     */
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
    EVP_PKEY *params = NULL;

    if (!pctx || EVP_PKEY_paramgen_init(pctx) <= 0)
        handle_errors();

    // Use standardized secure group ffdhe2048
    if (EVP_PKEY_CTX_set_group_name(pctx, "ffdhe2048") <= 0)
        handle_errors();

    if (EVP_PKEY_paramgen(pctx, &params) <= 0)
        handle_errors();

    printf("[%s] DH parameters generated (group: ffdhe2048).\n", my_id);

    /*
     * ------------------------------------------------------------------------
     * PHASE 2: Generate key pair
     * ------------------------------------------------------------------------
     */
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new(params, NULL);
    EVP_PKEY *my_key = NULL;

    if (!kctx || EVP_PKEY_keygen_init(kctx) <= 0)
        handle_errors();

    if (EVP_PKEY_keygen(kctx, &my_key) <= 0)
        handle_errors();

    printf("[%s] DH key pair generated successfully.\n", my_id);

    /*
     * ------------------------------------------------------------------------
     * PHASE 3: Export public key
     * ------------------------------------------------------------------------
     */
    BIO *out_bio = BIO_new_file(my_pub_name, "w");
    if (!out_bio) handle_errors();

    if (!PEM_write_bio_PUBKEY(out_bio, my_key))
        handle_errors();

    BIO_free(out_bio);

    printf("[%s] Public key saved to %s\n", my_id, my_pub_name);
    printf("[%s] Exchange this file with your peer and press ENTER to continue...\n", my_id);

    getchar();

    /*
     * ------------------------------------------------------------------------
     * PHASE 4: Load peer public key and derive secret
     * ------------------------------------------------------------------------
     */
    BIO *in_bio = BIO_new_file(peer_pub_name, "r");
    if (!in_bio) {
        fprintf(stderr, "[%s] Error: File %s not found\n", my_id, peer_pub_name);
        return EXIT_FAILURE;
    }

    EVP_PKEY *peer_pub = PEM_read_bio_PUBKEY(in_bio, NULL, NULL, NULL);
    BIO_free(in_bio);

    if (!peer_pub) handle_errors();

    printf("[%s] Peer public key loaded.\n", my_id);

    EVP_PKEY_CTX *dctx = EVP_PKEY_CTX_new(my_key, NULL);
    if (!dctx) handle_errors();

    if (EVP_PKEY_derive_init(dctx) <= 0)
        handle_errors();

    if (EVP_PKEY_derive_set_peer(dctx, peer_pub) <= 0)
        handle_errors();

    size_t secret_len;

    if (EVP_PKEY_derive(dctx, NULL, &secret_len) <= 0)
        handle_errors();

    unsigned char *secret = OPENSSL_malloc(secret_len);
    if (!secret) handle_errors();

    if (EVP_PKEY_derive(dctx, secret, &secret_len) <= 0)
        handle_errors();

    printf("[%s] Shared secret derived (%zu bytes).\n", my_id, secret_len);

    /*
     * ------------------------------------------------------------------------
     * PHASE 5: Derive AES key (SHA-256)
     * ------------------------------------------------------------------------
     */
    printf("[%s] Deriving AES key using SHA-256...\n", my_id);

    unsigned char aes_key[32];
    SHA256(secret, secret_len, aes_key);

    printf("[%s] AES key ready (first 128 bits used).\n", my_id);

    /*
     * ------------------------------------------------------------------------
     * PHASE 6: Encrypt local message
     * ------------------------------------------------------------------------
     */
    unsigned char iv[] = "static_iv_for_lab"; // NOT secure (lab only)

    unsigned char plaintext[1024];
    snprintf((char*)plaintext, sizeof(plaintext),
             "Ultra secret message from %s!", my_id);

    unsigned char ciphertext[1024];

    int c_len = aes_128_cbc_crypt(plaintext, strlen((char*)plaintext),
                                 aes_key, iv, ciphertext, 1);

    char my_enc_name[64];
    snprintf(my_enc_name, sizeof(my_enc_name), "%s_cipher.enc", my_id);

    FILE *f_enc = fopen(my_enc_name, "wb");
    fwrite(ciphertext, 1, c_len, f_enc);
    fclose(f_enc);

    printf("[%s] Encrypted file created: %s\n", my_id, my_enc_name);
    printf("[%s] Exchange encrypted files and press ENTER to continue...\n", my_id);

    getchar();

    /*
     * ------------------------------------------------------------------------
     * PHASE 7: Decrypt peer message
     * ------------------------------------------------------------------------
     */
    FILE *f_peer = fopen(peer_enc_name, "rb");
    if (!f_peer) {
        fprintf(stderr, "[%s] Error: File %s not found\n", my_id, peer_enc_name);
        return EXIT_FAILURE;
    }

    unsigned char peer_ctext[1024];
    unsigned char decrypted[1024];

    int pc_len = fread(peer_ctext, 1, sizeof(peer_ctext), f_peer);
    fclose(f_peer);

    int d_len = aes_128_cbc_crypt(peer_ctext, pc_len,
                                 aes_key, iv, decrypted, 0);

    decrypted[d_len] = '\0';

    printf("[%s] Decrypted message from %s:\n", my_id, peer_id);
    printf(">>> %s\n", decrypted);

    /*
     * ------------------------------------------------------------------------
     * Cleanup
     * ------------------------------------------------------------------------
     */
    OPENSSL_free(secret);
    EVP_PKEY_free(params);
    EVP_PKEY_free(my_key);
    EVP_PKEY_free(peer_pub);

    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_CTX_free(dctx);

    printf("[%s] Cleanup complete. Protocol finished successfully.\n", my_id);

    return EXIT_SUCCESS;
}