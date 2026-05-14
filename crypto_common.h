#ifndef CRYPTO_COMMON_H
#define CRYPTO_COMMON_H

#include <stdint.h>
#include <stddef.h>
#include <sodium.h>

#define KEY_SIZE 32
#define NONCE_SIZE 12
#define TAG_SIZE 16
#define COUNTER_SIZE 4

// Formato de paquete: [counter:4][ciphertext:var][tag:16]
typedef struct {
    uint32_t counter;
    uint8_t* ciphertext;
    size_t ciphertext_len;
    uint8_t tag[TAG_SIZE];
} encrypted_packet_t;

// Inicializar librería criptográfica
void crypto_init(void) {
    if (sodium_init() < 0) {
        // Error fatal
        while(1);
    }
}

#endif
