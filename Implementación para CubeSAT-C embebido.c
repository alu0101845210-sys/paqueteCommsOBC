#include "crypto_common.h"
#include <string.h>
#include <stdio.h>

// Simulación de EEPROM (en hardware real usar HAL_FLASH)
static uint32_t persistent_counter = 0;

// Leer contador desde memoria persistente
static uint32_t load_counter(void) {
    // En hardware real: leer desde EEPROM o FRAM
    return persistent_counter;
}

// Guardar contador en memoria persistente
static void save_counter(uint32_t counter) {
    persistent_counter = counter;
    // En hardware real: escribir en EEPROM verificar escritura
}

// Cifrar telemetría usando ChaCha20-Poly1305
// Input:  plaintext - datos a cifrar
//         len - longitud de plaintext
// Output: buffer - [counter(4)][ciphertext][tag(16)]
// Return: tamaño total del paquete cifrado (0 si error)
size_t encrypt_telemetry(const uint8_t* plaintext, size_t len, 
                         uint8_t* output, const uint8_t* key) {
    uint32_t counter;
    uint8_t nonce[NONCE_SIZE];
    size_t ciphertext_len;
    int result;
    
    // Cargar contador actual
    counter = load_counter();
    
    // Construir nonce: contador + zeros
    memset(nonce, 0, NONCE_SIZE);
    memcpy(nonce, &counter, COUNTER_SIZE);
    
    // Escribir contador al inicio del paquete
    memcpy(output, &counter, COUNTER_SIZE);
    
    // Cifrar y autenticar
    crypto_aead_chacha20poly1305_encrypt(
        output + COUNTER_SIZE,          // ciphertext
        &ciphertext_len,                // longitud ciphertext
        plaintext,                      // plaintext
        len,                            // longitud plaintext
        NULL, 0,                        // datos adicionales (AAD)
        NULL,                           // secret nonce (NULL = público)
        nonce,                          // nonce
        key                             // clave
    );
    
    if (result == 0) {
        // Incrementar y guardar contador
        counter++;
        save_counter(counter);
        
        // Retornar tamaño total: counter(4) + ciphertext + tag(16)
        return COUNTER_SIZE + ciphertext_len;
    }
    
    return 0; // Error
}

// Ejemplo de uso en CubeSAT
void send_telemetry(void) {
    uint8_t key[KEY_SIZE] = {0};  // En producción: clave precompartida
    uint8_t buffer[256];
    uint8_t telemetry[] = "TEMP:25.5C|BAT:92%|VOLT:3.85V";
    
    // Inicializar clave desde secure storage
    read_secure_key(key, KEY_SIZE);
    
    size_t enc_len = encrypt_telemetry(telemetry, sizeof(telemetry), 
                                        buffer, key);
    
    if (enc_len > 0) {
        // Transmitir por radio (UHF/S-band)
        radio_transmit(buffer, enc_len);
    }
}
