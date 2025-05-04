#include <openssl/ssl.h>
#include <picotls.h>
#include <picotls/openssl.h>
#include <stdio.h>
#include <string.h>

int main() {
  // Set up key
  uint8_t key[32] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                     0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                     0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                     0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};

  // Get cipher suite
  ptls_cipher_suite_t *suite = ptls_openssl_cipher_suites[0];
  if (!suite) {
    fprintf(stderr, "Failed to get cipher suite\n");
    return 1;
  }

  printf("Using cipher suite: %s\n", suite->aead->name);

  // Create AEAD encryption context
  ptls_aead_context_t *aead_encryption =
      ptls_aead_new(suite->aead, suite->hash, 1, key, "key-label");
  if (!aead_encryption) {
    fprintf(stderr, "Failed to create encryption context\n");
    return 1;
  }

  // Create AEAD decryption context
  ptls_aead_context_t *aead_decryption =
      ptls_aead_new(suite->aead, suite->hash, 0, key, "key-label");
  if (!aead_decryption) {
    fprintf(stderr, "Failed to create decryption context\n");
    ptls_aead_free(aead_encryption);
    return 1;
  }

  // Plain text to encrypt
  const char *message = "Hello, PicoTLS!";
  size_t message_len = strlen(message);

  // Allocate buffer for encrypted data
  size_t tag_size = suite->aead->tag_size;
  size_t encrypted_capacity = message_len + tag_size;
  uint8_t *encrypted = malloc(encrypted_capacity);
  if (!encrypted) {
    fprintf(stderr, "Memory allocation failed\n");
    ptls_aead_free(aead_encryption);
    ptls_aead_free(aead_decryption);
    return 1;
  }

  // Encrypt the message
  uint64_t seq = 0;
  size_t encrypted_len =
      ptls_aead_encrypt(aead_encryption, encrypted, (const uint8_t *)message,
                        message_len, seq, NULL, 0);

  if (encrypted_len == 0) {
    fprintf(stderr, "Encryption failed\n");
    free(encrypted);
    ptls_aead_free(aead_encryption);
    ptls_aead_free(aead_decryption);
    return 1;
  }

  printf("Plaintext (%zu bytes): %s\n", message_len, message);
  printf("Encrypted (%zu bytes): ", encrypted_len);
  for (size_t i = 0; i < encrypted_len; i++) {
    printf("%02x ", encrypted[i]);
  }
  printf("\n");

  // Allocate buffer for decrypted data
  uint8_t *decrypted = malloc(message_len);
  if (!decrypted) {
    fprintf(stderr, "Memory allocation failed\n");
    free(encrypted);
    ptls_aead_free(aead_encryption);
    ptls_aead_free(aead_decryption);
    return 1;
  }

  // Decrypt the message
  size_t decrypted_len = ptls_aead_decrypt(
      aead_decryption, decrypted, encrypted, encrypted_len, seq, NULL, 0);

  if (decrypted_len == SIZE_MAX) {
    fprintf(stderr, "Decryption failed\n");
    free(encrypted);
    free(decrypted);
    ptls_aead_free(aead_encryption);
    ptls_aead_free(aead_decryption);
    return 1;
  }

  // Null-terminate the decrypted message
  decrypted[decrypted_len] = '\0';
  printf("Decrypted (%zu bytes): %s\n", decrypted_len, (char *)decrypted);

  // Clean up
  free(encrypted);
  free(decrypted);
  ptls_aead_free(aead_encryption);
  ptls_aead_free(aead_decryption);

  return 0;
}
