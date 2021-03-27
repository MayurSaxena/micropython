#include "py/mpconfig.h"
#include <assert.h>
#include <string.h>

#include "py/nlr.h"
#include "py/runtime.h"
#include "esp_system.h"
#include "mbedtls/entropy.h"
#include "mbedtls/pk.h"
#include "mbedtls/ctr_drbg.h"

// Micro Python bindings

/// \classmethod \constructor([data])
/// initial data must be given if block_size wants to be passed

STATIC mp_obj_t getrandbits(mp_obj_t bits) {
    uint32_t num_cycles, i;
    vstr_t vstr;

    num_cycles = mp_obj_get_int(bits);
    num_cycles += 0x20 * ((num_cycles & 0x1F) != 0);  // round the bits to a multiple of 32
    num_cycles >>= 5;

    vstr_init_len(&vstr, num_cycles << 2); // going to get 32 bit integers (4 bytes)
    for (i = 0; i < num_cycles; i++) {
        *((uint32_t *) (vstr.buf + (i << 2))) = esp_random();
    }

    return mp_obj_new_str_from_vstr(&mp_type_bytes, &vstr);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(getrandbits_obj, getrandbits);

STATIC mp_obj_t mod_crypt_generate_rsa_signature(mp_uint_t n_args, const mp_obj_t *pos_args, mp_map_t *kw_args) {

    STATIC const mp_arg_t mod_pycom_generate_rsa_signature_args[] = {
        { MP_QSTR_message,                MP_ARG_OBJ | MP_ARG_REQUIRED, {} },
        { MP_QSTR_private_key,            MP_ARG_OBJ | MP_ARG_REQUIRED, {} },
        { MP_QSTR_pers,                   MP_ARG_OBJ | MP_ARG_KW_ONLY,  {.u_obj = MP_OBJ_NULL} }
    };

    // parse args
    mp_arg_val_t args[MP_ARRAY_SIZE(mod_pycom_generate_rsa_signature_args)];
    mp_arg_parse_all(n_args, pos_args, kw_args, MP_ARRAY_SIZE(mod_pycom_generate_rsa_signature_args), mod_pycom_generate_rsa_signature_args, args);

    const char* message = mp_obj_str_get_str(args[0].u_obj);
    const char* private_key = mp_obj_str_get_str(args[1].u_obj);

    char* pers="esp32-tls";
    if(args[2].u_obj != MP_OBJ_NULL) {
        pers = (char*)mp_obj_str_get_str(args[2].u_obj);
    }

    mbedtls_pk_context pk_context;
    mbedtls_pk_init(&pk_context);

    int rc = mbedtls_pk_parse_key(&pk_context, (const unsigned char*)private_key, strlen(private_key)+1, NULL, 0);
    if (rc != 0) {
        nlr_raise(mp_obj_new_exception_msg_varg(&mp_type_ValueError, "Invalid Private Key, error code: %d", rc));
    }

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    mbedtls_ctr_drbg_seed(
        &ctr_drbg,
        mbedtls_entropy_func,
        &entropy,
        (const unsigned char*)pers,
        strlen(pers));

    uint8_t digest[32];
    rc = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), (const unsigned char*)message, strlen(message), digest);
    if (rc != 0) {
        nlr_raise(mp_obj_new_exception_msg_varg(&mp_type_RuntimeError, "Message Digest operation failed, error code: %d", rc));
    }

    unsigned char *signature = malloc(5000);
    size_t signature_length;

    rc = mbedtls_pk_sign(&pk_context, MBEDTLS_MD_SHA256, digest, sizeof(digest), signature, &signature_length, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (rc != 0) {
        nlr_raise(mp_obj_new_exception_msg_varg(&mp_type_RuntimeError, "Signing failed, error code: %d!", rc));
    }

    mp_obj_t ret_signature = mp_obj_new_bytes((const byte*)signature, signature_length);

    mbedtls_pk_free(&pk_context);
    free((char*)signature);

    return ret_signature;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_KW(mod_crypt_generate_rsa_signature_obj, 2, mod_crypt_generate_rsa_signature);

STATIC mp_obj_t mod_crypt_rsa_encrypt(mp_uint_t n_args, const mp_obj_t *pos_args, mp_map_t *kw_args) {

    STATIC const mp_arg_t mod_pycom_generate_rsa_signature_args[] = {
        { MP_QSTR_message,                  MP_ARG_OBJ | MP_ARG_REQUIRED, {} },
        { MP_QSTR_key,                      MP_ARG_OBJ | MP_ARG_REQUIRED, {} },
    };

    // parse args
    mp_arg_val_t args[MP_ARRAY_SIZE(mod_pycom_generate_rsa_signature_args)];
    mp_arg_parse_all(n_args, pos_args, kw_args, MP_ARRAY_SIZE(mod_pycom_generate_rsa_signature_args), mod_pycom_generate_rsa_signature_args, args);

    const char* public_key = mp_obj_str_get_str(args[1].u_obj);

    mp_buffer_info_t message;
    mp_get_buffer_raise(args[0].u_obj, &message, MP_BUFFER_READ);

    char* pers="esp32-tls";

    mbedtls_pk_context pk_context;
    mbedtls_pk_init(&pk_context);

    int32_t rc = 0;
    rc = mbedtls_pk_parse_public_key(&pk_context, (const unsigned char*)public_key, strlen(public_key)+1);

    if (rc != 0) {
        nlr_raise(mp_obj_new_exception_msg_varg(&mp_type_ValueError, "Invalid public key, mbedtls error code: 0x%X", -rc));
    }

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    mbedtls_ctr_drbg_seed(
        &ctr_drbg,
        mbedtls_entropy_func,
        &entropy,
        (const unsigned char*)pers,
        strlen(pers));

    size_t output_len = message.len + 256;
    unsigned char *output = malloc(output_len);
    size_t output_actual_length = 0;

    rc = mbedtls_pk_encrypt(&pk_context,
            (const unsigned char*)message.buf,
            message.len,
            output,
            &output_actual_length,
            output_len,
            mbedtls_ctr_drbg_random,
            &ctr_drbg);

    if (rc != 0) {
        nlr_raise(mp_obj_new_exception_msg_varg(&mp_type_RuntimeError, "Encrypt failed, mbedtls error code: 0x%X!", -rc));
    }

    mp_obj_t ret_output = mp_obj_new_bytes((const byte*)output, output_actual_length);

    mbedtls_pk_free(&pk_context);
    free((char*)output);

    return ret_output;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_KW(mod_crypt_rsa_encrypt_obj, 2, mod_crypt_rsa_encrypt);

STATIC mp_obj_t mod_crypt_rsa_decrypt(mp_uint_t n_args, const mp_obj_t *pos_args, mp_map_t *kw_args) {

    STATIC const mp_arg_t mod_pycom_generate_rsa_signature_args[] = {
        { MP_QSTR_message,                  MP_ARG_OBJ | MP_ARG_REQUIRED, {} },
        { MP_QSTR_key,                      MP_ARG_OBJ | MP_ARG_REQUIRED, {} },
    };

    // parse args
    mp_arg_val_t args[MP_ARRAY_SIZE(mod_pycom_generate_rsa_signature_args)];
    mp_arg_parse_all(n_args, pos_args, kw_args, MP_ARRAY_SIZE(mod_pycom_generate_rsa_signature_args), mod_pycom_generate_rsa_signature_args, args);

    const char* private_key = mp_obj_str_get_str(args[1].u_obj);

    mp_buffer_info_t message;
    mp_get_buffer_raise(args[0].u_obj, &message, MP_BUFFER_READ);

    char* pers="esp32-tls";

    mbedtls_pk_context pk_context;
    mbedtls_pk_init(&pk_context);

    int32_t rc = 0;
    rc = mbedtls_pk_parse_key(&pk_context, (const unsigned char*)private_key, strlen(private_key)+1, NULL, 0);

    if (rc != 0) {
        nlr_raise(mp_obj_new_exception_msg_varg(&mp_type_ValueError, "Invalid private key, mbedtls error code: 0x%X", -rc));
    }

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    mbedtls_ctr_drbg_seed(
        &ctr_drbg,
        mbedtls_entropy_func,
        &entropy,
        (const unsigned char*)pers,
        strlen(pers));

    size_t output_len = message.len + 256;
    unsigned char *output = malloc(output_len);
    size_t output_actual_length = 0;

    rc = mbedtls_pk_decrypt(&pk_context,
            (const unsigned char*)message.buf,
            message.len,
            output,
            &output_actual_length,
            output_len,
            mbedtls_ctr_drbg_random,
            &ctr_drbg);

    if (rc != 0) {
        nlr_raise(mp_obj_new_exception_msg_varg(&mp_type_RuntimeError, "Decrypt failed, mbedtls error code: 0x%X!", -rc));
    }

    mp_obj_t ret_output = mp_obj_new_bytes((const byte*)output, output_actual_length);

    mbedtls_pk_free(&pk_context);
    free((char*)output);

    return ret_output;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_KW(mod_crypt_rsa_decrypt_obj, 2, mod_crypt_rsa_decrypt);



STATIC const mp_map_elem_t module_ursa_globals_table[] = {
    { MP_OBJ_NEW_QSTR(MP_QSTR___name__),                        MP_OBJ_NEW_QSTR(MP_QSTR_ursa) },
    { MP_OBJ_NEW_QSTR(MP_QSTR_getrandbits),                     (mp_obj_t)&getrandbits_obj },
    { MP_OBJ_NEW_QSTR(MP_QSTR_generate_rsa_signature),          (mp_obj_t)&mod_crypt_generate_rsa_signature_obj },
    { MP_OBJ_NEW_QSTR(MP_QSTR_rsa_encrypt),                     (mp_obj_t)&mod_crypt_rsa_encrypt_obj },
    { MP_OBJ_NEW_QSTR(MP_QSTR_rsa_decrypt),                     (mp_obj_t)&mod_crypt_rsa_decrypt_obj },
};

STATIC MP_DEFINE_CONST_DICT(module_ursa_globals, module_ursa_globals_table);

const mp_obj_module_t module_ursa = {
    .base = { &mp_type_module },
    .globals = (mp_obj_dict_t*)&module_ursa_globals,
};

MP_REGISTER_MODULE(MP_QSTR_ursa, module_ursa, CUSTOM_MODULE_URSA);
