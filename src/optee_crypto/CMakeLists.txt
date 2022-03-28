

project(opteecrypt VERSION 1.0.0)


add_library(opteecrypt STATIC
${OPTEE_SRC_FOLDER}/core/crypto/crypto.c
${OPTEE_SRC_FOLDER}/core/crypto/aes-gcm.c
${OPTEE_SRC_FOLDER}/core/crypto/aes-gcm-ghash-tbl.c
${OPTEE_SRC_FOLDER}/core/crypto/signed_hdr.c
${OPTEE_SRC_FOLDER}/core/crypto/cbc-mac.c
${OPTEE_SRC_FOLDER}/core/crypto/aes-cts.c
${OPTEE_SRC_FOLDER}/core/crypto/sm2-kdf.c
${OPTEE_SRC_FOLDER}/core/crypto/sm3.c
${OPTEE_SRC_FOLDER}/core/crypto/sm3-hash.c
${OPTEE_SRC_FOLDER}/core/crypto/sm3-hmac.c
${OPTEE_SRC_FOLDER}/core/crypto/sm4.c
${OPTEE_SRC_FOLDER}/core/crypto/sm4-cbc.c
${OPTEE_SRC_FOLDER}/core/crypto/sm4-ctr.c
${OPTEE_SRC_FOLDER}/core/crypto/sm4-ecb.c
rng_hw.c
sys.c
user_ta_entry.c
utee.c
sel4_user_ta.c
${OPTEE_SRC_FOLDER}/core/lib/libtomcrypt/hash.c
${OPTEE_SRC_FOLDER}/core/lib/libtomcrypt/hmac.c
${OPTEE_SRC_FOLDER}/core/lib/libtomcrypt/cmac.c
${OPTEE_SRC_FOLDER}/core/lib/libtomcrypt/ecb.c
${OPTEE_SRC_FOLDER}/core/lib/libtomcrypt/cbc.c
${OPTEE_SRC_FOLDER}/core/lib/libtomcrypt/ctr.c
${OPTEE_SRC_FOLDER}/core/lib/libtomcrypt/xts.c
${OPTEE_SRC_FOLDER}/core/lib/libtomcrypt/ccm.c
${OPTEE_SRC_FOLDER}/core/lib/libtomcrypt/gcm.c
${OPTEE_SRC_FOLDER}/core/lib/libtomcrypt/dsa.c
${OPTEE_SRC_FOLDER}/core/lib/libtomcrypt/ecc.c
${OPTEE_SRC_FOLDER}/core/lib/libtomcrypt/rsa.c
${OPTEE_SRC_FOLDER}/core/lib/libtomcrypt/dh.c
${OPTEE_SRC_FOLDER}/core/lib/libtomcrypt/aes.c
${OPTEE_SRC_FOLDER}/core/lib/libtomcrypt/sm2-dsa.c
${OPTEE_SRC_FOLDER}/core/lib/libtomcrypt/sm2-pke.c
${OPTEE_SRC_FOLDER}/core/lib/libtomcrypt/sm2-kep.c
${OPTEE_SRC_FOLDER}/core/lib/libtomcrypt/tomcrypt.c
${OPTEE_SRC_FOLDER}/lib/libutils/ext/memzero_explicit.c
${OPTEE_SRC_FOLDER}/core/tee/tee_cryp_concat_kdf.c
${OPTEE_SRC_FOLDER}/core/tee/tee_cryp_pbkdf2.c
${OPTEE_SRC_FOLDER}/core/tee/tee_cryp_hkdf.c
${OPTEE_SRC_FOLDER}/core/tee/tee_cryp_utl.c
${OPTEE_SRC_FOLDER}/core/tee/tee_fs_key_manager.c

# ${OPTEE_SRC_FOLDER}/core/tee/tee_fs_rpc.c
${OPTEE_SRC_FOLDER}/core/tee/tee_svc.c
${OPTEE_SRC_FOLDER}/core/tee/tee_svc_storage.c
${OPTEE_SRC_FOLDER}/core/tee/tee_svc_cryp.c
${OPTEE_SRC_FOLDER}/core/tee/tee_obj.c
${OPTEE_SRC_FOLDER}/core/tee/tee_pobj.c
${OPTEE_SRC_FOLDER}/core/tee/tee_time_generic.c
#${OPTEE_SRC_FOLDER}/core/tee/tee_ree_fs.c

${OPTEE_SRC_FOLDER}/core/kernel/huk_subkey.c
${OPTEE_SRC_FOLDER}/core/kernel/tee_misc.c
${OPTEE_SRC_FOLDER}/lib/libutils/ext/trace.c
${OPTEE_SRC_FOLDER}/lib/libutils/ext/snprintk.c
${OPTEE_SRC_FOLDER}/lib/libutils/ext/consttime_memcmp.c
${OPTEE_SRC_FOLDER}/lib/libutee/tee_api.c
${OPTEE_SRC_FOLDER}/lib/libutee/tee_api_panic.c
${OPTEE_SRC_FOLDER}/lib/libutee/tee_api_property.c
${OPTEE_SRC_FOLDER}/lib/libutee/tee_api_operations.c
${OPTEE_SRC_FOLDER}/lib/libutee/tee_api_objects.c
${OPTEE_SRC_FOLDER}/lib/libutee/tee_system_pta.c
${OPTEE_SRC_FOLDER}/lib/libutee/base64.c
${OPTEE_SRC_FOLDER}/lib/libutee/tee_uuid_from_str.c
${OPTEE_SRC_FOLDER}/ta/pkcs11/src/attributes.c
${OPTEE_SRC_FOLDER}/ta/pkcs11/src/entry.c
${OPTEE_SRC_FOLDER}/ta/pkcs11/src/handle.c
${OPTEE_SRC_FOLDER}/ta/pkcs11/src/object.c
${OPTEE_SRC_FOLDER}/ta/pkcs11/src/persistent_token.c
${OPTEE_SRC_FOLDER}/ta/pkcs11/src/pkcs11_attributes.c
${OPTEE_SRC_FOLDER}/ta/pkcs11/src/pkcs11_helpers.c
${OPTEE_SRC_FOLDER}/ta/pkcs11/src/pkcs11_token.c
${OPTEE_SRC_FOLDER}/ta/pkcs11/src/processing.c
${OPTEE_SRC_FOLDER}/ta/pkcs11/src/processing_aes.c
${OPTEE_SRC_FOLDER}/ta/pkcs11/src/processing_asymm.c
${OPTEE_SRC_FOLDER}/ta/pkcs11/src/processing_digest.c
${OPTEE_SRC_FOLDER}/ta/pkcs11/src/processing_ec.c
${OPTEE_SRC_FOLDER}/ta/pkcs11/src/processing_rsa.c
${OPTEE_SRC_FOLDER}/ta/pkcs11/src/processing_symm.c
${OPTEE_SRC_FOLDER}/ta/pkcs11/src/sanitize_object.c
${OPTEE_SRC_FOLDER}/ta/pkcs11/src/serializer.c
${OPTEE_SRC_FOLDER}/ta/pkcs11/src/token_capabilities.c
${OPTEE_SRC_FOLDER}/core/tee/tee_ramdisk_fs.c
)


list(APPEND opteecrypt_include_dirs
    "${TOMCRYPT_SRC_FOLDER}/src/headers"
    "${TOMCRYPT_SRC_FOLDER}/include"
    "${OPTEE_SRC_FOLDER}/core/include"
    "${OPTEE_SRC_FOLDER}/core/include/crypto"
    "${OPTEE_SRC_FOLDER}/core/include/tee"
    "${OPTEE_SRC_FOLDER}/lib/libutils/ext/include"
    "${OPTEE_SRC_FOLDER}/lib/libutee/include/"
    "${OPTEE_SRC_FOLDER}/ta/pkcs11/include"
    "${project_dir}/projects/sel4_teeos/include"
    "${OPTEE_SRC_FOLDER}/ta/pkcs11/src"
    "${OPTEE_SRC_FOLDER}/ta/pkcs11/include"
    "include"
)

target_include_directories(opteecrypt
PUBLIC
    ${opteecrypt_include_dirs}
)


target_compile_definitions(opteecrypt PUBLIC
CFG_CRYPTO_CBC_MAC_BUNDLE_BLOCKS=64
CFG_CRYPTO_MD5
CFG_CRYPTO_SHA1
CFG_CRYPTO_SHA256
CFG_CRYPTO_SHA224
CFG_CRYPTO_SHA384
CFG_CRYPTO_SHA512
CFG_CRYPTO_SM3
CFG_CRYPTO_SM4
CFG_CRYPTO_CBC_MAC
CFG_CRYPTO_HMAC
CFG_CRYPTO_CMAC
CFG_AES_GCM_TABLE_BASED
CFG_CRYPTO_AES
CFG_CRYPTO_CTS
CFG_CRYPTO_XTS
CFG_CRYPTO_CTR
CFG_CRYPTO_CBC
CFG_CRYPTO_ECB
CFG_CRYPTO_DES
CFG_CRYPTO_ECC
CFG_CRYPTO_RSA
CFG_CRYPTO_RSASSA_NA1
LTC_GCM_MODE
LTC_EASY
_CFG_CORE_LTC_SM2_PKE
_CFG_CORE_LTC_SM2_DSA
_CFG_CORE_LTC_AES
_CFG_CORE_LTC_DES
_CFG_CORE_LTC_MD5
_CFG_CORE_LTC_SHA1
_CFG_CORE_LTC_SHA224
_CFG_CORE_LTC_SHA256
_CFG_CORE_LTC_SHA384
_CFG_CORE_LTC_SHA512
_CFG_CORE_LTC_BIGNUM_MAX_BITS=4096
CFG_CORE_BIGNUM_MAX_BITS=4096
CFG_TA_BIGNUM_MAX_BITS=2048
CFG_CRYPTOLIB_NAME_tomcrypt
CFG_MSG_LONG_PREFIX_MASK=0x1f
CFG_TEE_CORE_LOG_LEVEL=4
TRACE_LEVEL=TRACE_INFO
OPTEE_RAMDISK_TRACE_LEVEL=TRACE_ERROR
TRACE_ERROR_HIGHLIGHT
CFG_PKCS11_TA_TOKEN_COUNT=3
#CFG_REE_FS
THREAD_RPC_MAX_NUM_PARAMS=4
CFG_WITH_USER_TA
CFG_TEE_TA_LOG_LEVEL=1
CFG_PKCS11_TA_HEAP_SIZE=32768
CFG_PKCS11_TA_AUTH_TEE_IDENTITY
CFG_PKCS11_TA_ALLOW_DIGEST_KEY
CFG_TEE_API_VERSION=GPD-1.1-dev
CFG_RAMDISK_FS
)

target_compile_options(opteecrypt
    PRIVATE
        -Wall
        -Werror
        -O2
)

target_link_libraries(opteecrypt
    PUBLIC
        muslc
        sel4
        sel4runtime
        sel4utils
        sel4platsupport
        sel4_autoconf
    PRIVATE
        teeos_Config
        tomcrypt
        tommath
        sysctllib
        littlefs
)

export(PACKAGE ${PROJECT_NAME})