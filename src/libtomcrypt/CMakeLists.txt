#
# Copyright 2022, Unikie
#
# SPDX-License-Identifier: BSD-2-Clause
#

project(tomcrypt VERSION 1.3.0)


add_library(tomcrypt STATIC
${TOMCRYPT_SRC_FOLDER}/src/ciphers/aes/aes.c
${TOMCRYPT_SRC_FOLDER}/src/ciphers/aes/aes_tab.c
${TOMCRYPT_SRC_FOLDER}/src/ciphers/anubis.c ${TOMCRYPT_SRC_FOLDER}/src/ciphers/blowfish.c 
${TOMCRYPT_SRC_FOLDER}/src/ciphers/camellia.c ${TOMCRYPT_SRC_FOLDER}/src/ciphers/cast5.c ${TOMCRYPT_SRC_FOLDER}/src/ciphers/des.c ${TOMCRYPT_SRC_FOLDER}/src/ciphers/idea.c ${TOMCRYPT_SRC_FOLDER}/src/ciphers/kasumi.c 
${TOMCRYPT_SRC_FOLDER}/src/ciphers/khazad.c ${TOMCRYPT_SRC_FOLDER}/src/ciphers/kseed.c ${TOMCRYPT_SRC_FOLDER}/src/ciphers/multi2.c ${TOMCRYPT_SRC_FOLDER}/src/ciphers/noekeon.c ${TOMCRYPT_SRC_FOLDER}/src/ciphers/rc2.c 
${TOMCRYPT_SRC_FOLDER}/src/ciphers/rc5.c ${TOMCRYPT_SRC_FOLDER}/src/ciphers/rc6.c ${TOMCRYPT_SRC_FOLDER}/src/ciphers/safer/safer.c ${TOMCRYPT_SRC_FOLDER}/src/ciphers/safer/saferp.c 
${TOMCRYPT_SRC_FOLDER}/src/ciphers/serpent.c ${TOMCRYPT_SRC_FOLDER}/src/ciphers/skipjack.c  ${TOMCRYPT_SRC_FOLDER}/src/ciphers/twofish/twofish.c 
${TOMCRYPT_SRC_FOLDER}/src/ciphers/xtea.c ${TOMCRYPT_SRC_FOLDER}/src/encauth/ccm/ccm_add_aad.c ${TOMCRYPT_SRC_FOLDER}/src/encauth/ccm/ccm_add_nonce.c 
${TOMCRYPT_SRC_FOLDER}/src/encauth/ccm/ccm_done.c ${TOMCRYPT_SRC_FOLDER}/src/encauth/ccm/ccm_init.c ${TOMCRYPT_SRC_FOLDER}/src/encauth/ccm/ccm_memory.c 
${TOMCRYPT_SRC_FOLDER}/src/encauth/ccm/ccm_process.c ${TOMCRYPT_SRC_FOLDER}/src/encauth/ccm/ccm_reset.c ${TOMCRYPT_SRC_FOLDER}/src/encauth/ccm/ccm_test.c 
${TOMCRYPT_SRC_FOLDER}/src/encauth/chachapoly/chacha20poly1305_add_aad.c ${TOMCRYPT_SRC_FOLDER}/src/encauth/chachapoly/chacha20poly1305_decrypt.c 
${TOMCRYPT_SRC_FOLDER}/src/encauth/chachapoly/chacha20poly1305_done.c ${TOMCRYPT_SRC_FOLDER}/src/encauth/chachapoly/chacha20poly1305_encrypt.c 
${TOMCRYPT_SRC_FOLDER}/src/encauth/chachapoly/chacha20poly1305_init.c ${TOMCRYPT_SRC_FOLDER}/src/encauth/chachapoly/chacha20poly1305_memory.c 
${TOMCRYPT_SRC_FOLDER}/src/encauth/chachapoly/chacha20poly1305_setiv.c 
${TOMCRYPT_SRC_FOLDER}/src/encauth/chachapoly/chacha20poly1305_setiv_rfc7905.c 
${TOMCRYPT_SRC_FOLDER}/src/encauth/chachapoly/chacha20poly1305_test.c ${TOMCRYPT_SRC_FOLDER}/src/encauth/eax/eax_addheader.c 
${TOMCRYPT_SRC_FOLDER}/src/encauth/eax/eax_decrypt.c ${TOMCRYPT_SRC_FOLDER}/src/encauth/eax/eax_decrypt_verify_memory.c ${TOMCRYPT_SRC_FOLDER}/src/encauth/eax/eax_done.c 
${TOMCRYPT_SRC_FOLDER}/src/encauth/eax/eax_encrypt.c ${TOMCRYPT_SRC_FOLDER}/src/encauth/eax/eax_encrypt_authenticate_memory.c 
${TOMCRYPT_SRC_FOLDER}/src/encauth/eax/eax_init.c ${TOMCRYPT_SRC_FOLDER}/src/encauth/eax/eax_test.c ${TOMCRYPT_SRC_FOLDER}/src/encauth/gcm/gcm_add_aad.c 
${TOMCRYPT_SRC_FOLDER}/src/encauth/gcm/gcm_add_iv.c ${TOMCRYPT_SRC_FOLDER}/src/encauth/gcm/gcm_done.c ${TOMCRYPT_SRC_FOLDER}/src/encauth/gcm/gcm_gf_mult.c 
${TOMCRYPT_SRC_FOLDER}/src/encauth/gcm/gcm_init.c ${TOMCRYPT_SRC_FOLDER}/src/encauth/gcm/gcm_memory.c ${TOMCRYPT_SRC_FOLDER}/src/encauth/gcm/gcm_mult_h.c 
${TOMCRYPT_SRC_FOLDER}/src/encauth/gcm/gcm_process.c ${TOMCRYPT_SRC_FOLDER}/src/encauth/gcm/gcm_reset.c ${TOMCRYPT_SRC_FOLDER}/src/encauth/gcm/gcm_test.c 
${TOMCRYPT_SRC_FOLDER}/src/encauth/ocb/ocb_decrypt.c ${TOMCRYPT_SRC_FOLDER}/src/encauth/ocb/ocb_decrypt_verify_memory.c 
${TOMCRYPT_SRC_FOLDER}/src/encauth/ocb/ocb_done_decrypt.c ${TOMCRYPT_SRC_FOLDER}/src/encauth/ocb/ocb_done_encrypt.c ${TOMCRYPT_SRC_FOLDER}/src/encauth/ocb/ocb_encrypt.c 
${TOMCRYPT_SRC_FOLDER}/src/encauth/ocb/ocb_encrypt_authenticate_memory.c ${TOMCRYPT_SRC_FOLDER}/src/encauth/ocb/ocb_init.c ${TOMCRYPT_SRC_FOLDER}/src/encauth/ocb/ocb_ntz.c 
${TOMCRYPT_SRC_FOLDER}/src/encauth/ocb/ocb_shift_xor.c ${TOMCRYPT_SRC_FOLDER}/src/encauth/ocb/ocb_test.c ${TOMCRYPT_SRC_FOLDER}/src/encauth/ocb/s_ocb_done.c 
${TOMCRYPT_SRC_FOLDER}/src/encauth/ocb3/ocb3_add_aad.c ${TOMCRYPT_SRC_FOLDER}/src/encauth/ocb3/ocb3_decrypt.c ${TOMCRYPT_SRC_FOLDER}/src/encauth/ocb3/ocb3_decrypt_last.c 
${TOMCRYPT_SRC_FOLDER}/src/encauth/ocb3/ocb3_decrypt_verify_memory.c ${TOMCRYPT_SRC_FOLDER}/src/encauth/ocb3/ocb3_done.c 
${TOMCRYPT_SRC_FOLDER}/src/encauth/ocb3/ocb3_encrypt.c ${TOMCRYPT_SRC_FOLDER}/src/encauth/ocb3/ocb3_encrypt_authenticate_memory.c 
${TOMCRYPT_SRC_FOLDER}/src/encauth/ocb3/ocb3_encrypt_last.c ${TOMCRYPT_SRC_FOLDER}/src/encauth/ocb3/ocb3_init.c ${TOMCRYPT_SRC_FOLDER}/src/encauth/ocb3/ocb3_int_ntz.c 
${TOMCRYPT_SRC_FOLDER}/src/encauth/ocb3/ocb3_int_xor_blocks.c ${TOMCRYPT_SRC_FOLDER}/src/encauth/ocb3/ocb3_test.c ${TOMCRYPT_SRC_FOLDER}/src/hashes/blake2b.c 
${TOMCRYPT_SRC_FOLDER}/src/hashes/blake2s.c ${TOMCRYPT_SRC_FOLDER}/src/hashes/chc/chc.c ${TOMCRYPT_SRC_FOLDER}/src/hashes/helper/hash_file.c 
${TOMCRYPT_SRC_FOLDER}/src/hashes/helper/hash_filehandle.c ${TOMCRYPT_SRC_FOLDER}/src/hashes/helper/hash_memory.c 
${TOMCRYPT_SRC_FOLDER}/src/hashes/helper/hash_memory_multi.c ${TOMCRYPT_SRC_FOLDER}/src/hashes/md2.c ${TOMCRYPT_SRC_FOLDER}/src/hashes/md4.c ${TOMCRYPT_SRC_FOLDER}/src/hashes/md5.c 
${TOMCRYPT_SRC_FOLDER}/src/hashes/rmd128.c ${TOMCRYPT_SRC_FOLDER}/src/hashes/rmd160.c ${TOMCRYPT_SRC_FOLDER}/src/hashes/rmd256.c ${TOMCRYPT_SRC_FOLDER}/src/hashes/rmd320.c ${TOMCRYPT_SRC_FOLDER}/src/hashes/sha1.c 
${TOMCRYPT_SRC_FOLDER}/src/hashes/sha2/sha224.c ${TOMCRYPT_SRC_FOLDER}/src/hashes/sha2/sha256.c ${TOMCRYPT_SRC_FOLDER}/src/hashes/sha2/sha384.c ${TOMCRYPT_SRC_FOLDER}/src/hashes/sha2/sha512.c 
${TOMCRYPT_SRC_FOLDER}/src/hashes/sha2/sha512_224.c ${TOMCRYPT_SRC_FOLDER}/src/hashes/sha2/sha512_256.c ${TOMCRYPT_SRC_FOLDER}/src/hashes/sha3.c ${TOMCRYPT_SRC_FOLDER}/src/hashes/sha3_test.c 
${TOMCRYPT_SRC_FOLDER}/src/hashes/tiger.c ${TOMCRYPT_SRC_FOLDER}/src/hashes/whirl/whirl.c ${TOMCRYPT_SRC_FOLDER}/src/mac/blake2/blake2bmac.c 
${TOMCRYPT_SRC_FOLDER}/src/mac/blake2/blake2bmac_file.c ${TOMCRYPT_SRC_FOLDER}/src/mac/blake2/blake2bmac_memory.c 
${TOMCRYPT_SRC_FOLDER}/src/mac/blake2/blake2bmac_memory_multi.c ${TOMCRYPT_SRC_FOLDER}/src/mac/blake2/blake2bmac_test.c ${TOMCRYPT_SRC_FOLDER}/src/mac/blake2/blake2smac.c 
${TOMCRYPT_SRC_FOLDER}/src/mac/blake2/blake2smac_file.c ${TOMCRYPT_SRC_FOLDER}/src/mac/blake2/blake2smac_memory.c 
${TOMCRYPT_SRC_FOLDER}/src/mac/blake2/blake2smac_memory_multi.c ${TOMCRYPT_SRC_FOLDER}/src/mac/blake2/blake2smac_test.c ${TOMCRYPT_SRC_FOLDER}/src/mac/f9/f9_done.c 
${TOMCRYPT_SRC_FOLDER}/src/mac/f9/f9_file.c ${TOMCRYPT_SRC_FOLDER}/src/mac/f9/f9_init.c ${TOMCRYPT_SRC_FOLDER}/src/mac/f9/f9_memory.c ${TOMCRYPT_SRC_FOLDER}/src/mac/f9/f9_memory_multi.c 
${TOMCRYPT_SRC_FOLDER}/src/mac/f9/f9_process.c ${TOMCRYPT_SRC_FOLDER}/src/mac/f9/f9_test.c ${TOMCRYPT_SRC_FOLDER}/src/mac/hmac/hmac_done.c ${TOMCRYPT_SRC_FOLDER}/src/mac/hmac/hmac_file.c 
${TOMCRYPT_SRC_FOLDER}/src/mac/hmac/hmac_init.c ${TOMCRYPT_SRC_FOLDER}/src/mac/hmac/hmac_memory.c ${TOMCRYPT_SRC_FOLDER}/src/mac/hmac/hmac_memory_multi.c 
${TOMCRYPT_SRC_FOLDER}/src/mac/hmac/hmac_process.c ${TOMCRYPT_SRC_FOLDER}/src/mac/hmac/hmac_test.c ${TOMCRYPT_SRC_FOLDER}/src/mac/omac/omac_done.c ${TOMCRYPT_SRC_FOLDER}/src/mac/omac/omac_file.c 
${TOMCRYPT_SRC_FOLDER}/src/mac/omac/omac_init.c ${TOMCRYPT_SRC_FOLDER}/src/mac/omac/omac_memory.c ${TOMCRYPT_SRC_FOLDER}/src/mac/omac/omac_memory_multi.c 
${TOMCRYPT_SRC_FOLDER}/src/mac/omac/omac_process.c ${TOMCRYPT_SRC_FOLDER}/src/mac/omac/omac_test.c ${TOMCRYPT_SRC_FOLDER}/src/mac/pelican/pelican.c 
${TOMCRYPT_SRC_FOLDER}/src/mac/pelican/pelican_memory.c ${TOMCRYPT_SRC_FOLDER}/src/mac/pelican/pelican_test.c ${TOMCRYPT_SRC_FOLDER}/src/mac/pmac/pmac_done.c 
${TOMCRYPT_SRC_FOLDER}/src/mac/pmac/pmac_file.c ${TOMCRYPT_SRC_FOLDER}/src/mac/pmac/pmac_init.c ${TOMCRYPT_SRC_FOLDER}/src/mac/pmac/pmac_memory.c 
${TOMCRYPT_SRC_FOLDER}/src/mac/pmac/pmac_memory_multi.c ${TOMCRYPT_SRC_FOLDER}/src/mac/pmac/pmac_ntz.c ${TOMCRYPT_SRC_FOLDER}/src/mac/pmac/pmac_process.c 
${TOMCRYPT_SRC_FOLDER}/src/mac/pmac/pmac_shift_xor.c ${TOMCRYPT_SRC_FOLDER}/src/mac/pmac/pmac_test.c ${TOMCRYPT_SRC_FOLDER}/src/mac/poly1305/poly1305.c 
${TOMCRYPT_SRC_FOLDER}/src/mac/poly1305/poly1305_file.c ${TOMCRYPT_SRC_FOLDER}/src/mac/poly1305/poly1305_memory.c 
${TOMCRYPT_SRC_FOLDER}/src/mac/poly1305/poly1305_memory_multi.c ${TOMCRYPT_SRC_FOLDER}/src/mac/poly1305/poly1305_test.c ${TOMCRYPT_SRC_FOLDER}/src/mac/xcbc/xcbc_done.c 
${TOMCRYPT_SRC_FOLDER}/src/mac/xcbc/xcbc_file.c ${TOMCRYPT_SRC_FOLDER}/src/mac/xcbc/xcbc_init.c ${TOMCRYPT_SRC_FOLDER}/src/mac/xcbc/xcbc_memory.c 
${TOMCRYPT_SRC_FOLDER}/src/mac/xcbc/xcbc_memory_multi.c ${TOMCRYPT_SRC_FOLDER}/src/mac/xcbc/xcbc_process.c ${TOMCRYPT_SRC_FOLDER}/src/mac/xcbc/xcbc_test.c 
${TOMCRYPT_SRC_FOLDER}/src/math/fp/ltc_ecc_fp_mulmod.c ${TOMCRYPT_SRC_FOLDER}/src/math/gmp_desc.c ${TOMCRYPT_SRC_FOLDER}/src/math/ltm_desc.c ${TOMCRYPT_SRC_FOLDER}/src/math/multi.c 
${TOMCRYPT_SRC_FOLDER}/src/math/radix_to_bin.c ${TOMCRYPT_SRC_FOLDER}/src/math/rand_bn.c ${TOMCRYPT_SRC_FOLDER}/src/math/rand_prime.c ${TOMCRYPT_SRC_FOLDER}/src/math/tfm_desc.c ${TOMCRYPT_SRC_FOLDER}/src/misc/adler32.c 
${TOMCRYPT_SRC_FOLDER}/src/misc/base16/base16_decode.c ${TOMCRYPT_SRC_FOLDER}/src/misc/base16/base16_encode.c ${TOMCRYPT_SRC_FOLDER}/src/misc/base32/base32_decode.c 
${TOMCRYPT_SRC_FOLDER}/src/misc/base32/base32_encode.c ${TOMCRYPT_SRC_FOLDER}/src/misc/base64/base64_decode.c ${TOMCRYPT_SRC_FOLDER}/src/misc/base64/base64_encode.c 
${TOMCRYPT_SRC_FOLDER}/src/misc/burn_stack.c ${TOMCRYPT_SRC_FOLDER}/src/misc/compare_testvector.c ${TOMCRYPT_SRC_FOLDER}/src/misc/copy_or_zeromem.c 
${TOMCRYPT_SRC_FOLDER}/src/misc/crc32.c ${TOMCRYPT_SRC_FOLDER}/src/misc/crypt/crypt.c ${TOMCRYPT_SRC_FOLDER}/src/misc/crypt/crypt_argchk.c 
${TOMCRYPT_SRC_FOLDER}/src/misc/crypt/crypt_cipher_descriptor.c ${TOMCRYPT_SRC_FOLDER}/src/misc/crypt/crypt_cipher_is_valid.c 
${TOMCRYPT_SRC_FOLDER}/src/misc/crypt/crypt_constants.c ${TOMCRYPT_SRC_FOLDER}/src/misc/crypt/crypt_find_cipher.c 
${TOMCRYPT_SRC_FOLDER}/src/misc/crypt/crypt_find_cipher_any.c ${TOMCRYPT_SRC_FOLDER}/src/misc/crypt/crypt_find_cipher_id.c 
${TOMCRYPT_SRC_FOLDER}/src/misc/crypt/crypt_find_hash.c ${TOMCRYPT_SRC_FOLDER}/src/misc/crypt/crypt_find_hash_any.c 
${TOMCRYPT_SRC_FOLDER}/src/misc/crypt/crypt_find_hash_id.c ${TOMCRYPT_SRC_FOLDER}/src/misc/crypt/crypt_find_hash_oid.c 
${TOMCRYPT_SRC_FOLDER}/src/misc/crypt/crypt_find_prng.c ${TOMCRYPT_SRC_FOLDER}/src/misc/crypt/crypt_fsa.c ${TOMCRYPT_SRC_FOLDER}/src/misc/crypt/crypt_hash_descriptor.c 
${TOMCRYPT_SRC_FOLDER}/src/misc/crypt/crypt_hash_is_valid.c ${TOMCRYPT_SRC_FOLDER}/src/misc/crypt/crypt_inits.c 
${TOMCRYPT_SRC_FOLDER}/src/misc/crypt/crypt_ltc_mp_descriptor.c ${TOMCRYPT_SRC_FOLDER}/src/misc/crypt/crypt_prng_descriptor.c 
${TOMCRYPT_SRC_FOLDER}/src/misc/crypt/crypt_prng_is_valid.c ${TOMCRYPT_SRC_FOLDER}/src/misc/crypt/crypt_prng_rng_descriptor.c 
${TOMCRYPT_SRC_FOLDER}/src/misc/crypt/crypt_register_all_ciphers.c ${TOMCRYPT_SRC_FOLDER}/src/misc/crypt/crypt_register_all_hashes.c 
${TOMCRYPT_SRC_FOLDER}/src/misc/crypt/crypt_register_all_prngs.c ${TOMCRYPT_SRC_FOLDER}/src/misc/crypt/crypt_register_cipher.c 
${TOMCRYPT_SRC_FOLDER}/src/misc/crypt/crypt_register_hash.c ${TOMCRYPT_SRC_FOLDER}/src/misc/crypt/crypt_register_prng.c ${TOMCRYPT_SRC_FOLDER}/src/misc/crypt/crypt_sizes.c 
${TOMCRYPT_SRC_FOLDER}/src/misc/crypt/crypt_unregister_cipher.c ${TOMCRYPT_SRC_FOLDER}/src/misc/crypt/crypt_unregister_hash.c 
${TOMCRYPT_SRC_FOLDER}/src/misc/crypt/crypt_unregister_prng.c ${TOMCRYPT_SRC_FOLDER}/src/misc/error_to_string.c ${TOMCRYPT_SRC_FOLDER}/src/misc/hkdf/hkdf.c 
${TOMCRYPT_SRC_FOLDER}/src/misc/hkdf/hkdf_test.c ${TOMCRYPT_SRC_FOLDER}/src/misc/mem_neq.c ${TOMCRYPT_SRC_FOLDER}/src/misc/padding/padding_depad.c 
${TOMCRYPT_SRC_FOLDER}/src/misc/padding/padding_pad.c ${TOMCRYPT_SRC_FOLDER}/src/misc/pbes/pbes.c ${TOMCRYPT_SRC_FOLDER}/src/misc/pbes/pbes1.c ${TOMCRYPT_SRC_FOLDER}/src/misc/pbes/pbes2.c 
${TOMCRYPT_SRC_FOLDER}/src/misc/pkcs12/pkcs12_kdf.c ${TOMCRYPT_SRC_FOLDER}/src/misc/pkcs12/pkcs12_utf8_to_utf16.c ${TOMCRYPT_SRC_FOLDER}/src/misc/pkcs5/pkcs_5_1.c 
${TOMCRYPT_SRC_FOLDER}/src/misc/pkcs5/pkcs_5_2.c ${TOMCRYPT_SRC_FOLDER}/src/misc/pkcs5/pkcs_5_test.c ${TOMCRYPT_SRC_FOLDER}/src/misc/ssh/ssh_decode_sequence_multi.c 
${TOMCRYPT_SRC_FOLDER}/src/misc/ssh/ssh_encode_sequence_multi.c ${TOMCRYPT_SRC_FOLDER}/src/misc/zeromem.c ${TOMCRYPT_SRC_FOLDER}/src/modes/cbc/cbc_decrypt.c 
${TOMCRYPT_SRC_FOLDER}/src/modes/cbc/cbc_done.c ${TOMCRYPT_SRC_FOLDER}/src/modes/cbc/cbc_encrypt.c ${TOMCRYPT_SRC_FOLDER}/src/modes/cbc/cbc_getiv.c 
${TOMCRYPT_SRC_FOLDER}/src/modes/cbc/cbc_setiv.c ${TOMCRYPT_SRC_FOLDER}/src/modes/cbc/cbc_start.c ${TOMCRYPT_SRC_FOLDER}/src/modes/cfb/cfb_decrypt.c 
${TOMCRYPT_SRC_FOLDER}/src/modes/cfb/cfb_done.c ${TOMCRYPT_SRC_FOLDER}/src/modes/cfb/cfb_encrypt.c ${TOMCRYPT_SRC_FOLDER}/src/modes/cfb/cfb_getiv.c 
${TOMCRYPT_SRC_FOLDER}/src/modes/cfb/cfb_setiv.c ${TOMCRYPT_SRC_FOLDER}/src/modes/cfb/cfb_start.c ${TOMCRYPT_SRC_FOLDER}/src/modes/ctr/ctr_decrypt.c 
${TOMCRYPT_SRC_FOLDER}/src/modes/ctr/ctr_done.c ${TOMCRYPT_SRC_FOLDER}/src/modes/ctr/ctr_encrypt.c ${TOMCRYPT_SRC_FOLDER}/src/modes/ctr/ctr_getiv.c 
${TOMCRYPT_SRC_FOLDER}/src/modes/ctr/ctr_setiv.c ${TOMCRYPT_SRC_FOLDER}/src/modes/ctr/ctr_start.c ${TOMCRYPT_SRC_FOLDER}/src/modes/ctr/ctr_test.c 
${TOMCRYPT_SRC_FOLDER}/src/modes/ecb/ecb_decrypt.c ${TOMCRYPT_SRC_FOLDER}/src/modes/ecb/ecb_done.c ${TOMCRYPT_SRC_FOLDER}/src/modes/ecb/ecb_encrypt.c 
${TOMCRYPT_SRC_FOLDER}/src/modes/ecb/ecb_start.c ${TOMCRYPT_SRC_FOLDER}/src/modes/f8/f8_decrypt.c ${TOMCRYPT_SRC_FOLDER}/src/modes/f8/f8_done.c ${TOMCRYPT_SRC_FOLDER}/src/modes/f8/f8_encrypt.c 
${TOMCRYPT_SRC_FOLDER}/src/modes/f8/f8_getiv.c ${TOMCRYPT_SRC_FOLDER}/src/modes/f8/f8_setiv.c ${TOMCRYPT_SRC_FOLDER}/src/modes/f8/f8_start.c ${TOMCRYPT_SRC_FOLDER}/src/modes/f8/f8_test_mode.c 
${TOMCRYPT_SRC_FOLDER}/src/modes/lrw/lrw_decrypt.c ${TOMCRYPT_SRC_FOLDER}/src/modes/lrw/lrw_done.c ${TOMCRYPT_SRC_FOLDER}/src/modes/lrw/lrw_encrypt.c 
${TOMCRYPT_SRC_FOLDER}/src/modes/lrw/lrw_getiv.c ${TOMCRYPT_SRC_FOLDER}/src/modes/lrw/lrw_process.c ${TOMCRYPT_SRC_FOLDER}/src/modes/lrw/lrw_setiv.c 
${TOMCRYPT_SRC_FOLDER}/src/modes/lrw/lrw_start.c ${TOMCRYPT_SRC_FOLDER}/src/modes/lrw/lrw_test.c ${TOMCRYPT_SRC_FOLDER}/src/modes/ofb/ofb_decrypt.c ${TOMCRYPT_SRC_FOLDER}/src/modes/ofb/ofb_done.c 
${TOMCRYPT_SRC_FOLDER}/src/modes/ofb/ofb_encrypt.c ${TOMCRYPT_SRC_FOLDER}/src/modes/ofb/ofb_getiv.c ${TOMCRYPT_SRC_FOLDER}/src/modes/ofb/ofb_setiv.c 
${TOMCRYPT_SRC_FOLDER}/src/modes/ofb/ofb_start.c ${TOMCRYPT_SRC_FOLDER}/src/modes/xts/xts_decrypt.c ${TOMCRYPT_SRC_FOLDER}/src/modes/xts/xts_done.c 
${TOMCRYPT_SRC_FOLDER}/src/modes/xts/xts_encrypt.c ${TOMCRYPT_SRC_FOLDER}/src/modes/xts/xts_init.c ${TOMCRYPT_SRC_FOLDER}/src/modes/xts/xts_mult_x.c 
${TOMCRYPT_SRC_FOLDER}/src/modes/xts/xts_test.c ${TOMCRYPT_SRC_FOLDER}/src/pk/asn1/der/bit/der_decode_bit_string.c 
${TOMCRYPT_SRC_FOLDER}/src/pk/asn1/der/bit/der_decode_raw_bit_string.c ${TOMCRYPT_SRC_FOLDER}/src/pk/asn1/der/bit/der_encode_bit_string.c 
${TOMCRYPT_SRC_FOLDER}/src/pk/asn1/der/bit/der_encode_raw_bit_string.c ${TOMCRYPT_SRC_FOLDER}/src/pk/asn1/der/bit/der_length_bit_string.c 
${TOMCRYPT_SRC_FOLDER}/src/pk/asn1/der/boolean/der_decode_boolean.c ${TOMCRYPT_SRC_FOLDER}/src/pk/asn1/der/boolean/der_encode_boolean.c 
${TOMCRYPT_SRC_FOLDER}/src/pk/asn1/der/boolean/der_length_boolean.c ${TOMCRYPT_SRC_FOLDER}/src/pk/asn1/der/choice/der_decode_choice.c 
${TOMCRYPT_SRC_FOLDER}/src/pk/asn1/der/custom_type/der_decode_custom_type.c 
${TOMCRYPT_SRC_FOLDER}/src/pk/asn1/der/custom_type/der_encode_custom_type.c 
${TOMCRYPT_SRC_FOLDER}/src/pk/asn1/der/custom_type/der_length_custom_type.c ${TOMCRYPT_SRC_FOLDER}/src/pk/asn1/der/general/der_asn1_maps.c 
${TOMCRYPT_SRC_FOLDER}/src/pk/asn1/der/general/der_decode_asn1_identifier.c ${TOMCRYPT_SRC_FOLDER}/src/pk/asn1/der/general/der_decode_asn1_length.c 
${TOMCRYPT_SRC_FOLDER}/src/pk/asn1/der/general/der_encode_asn1_identifier.c ${TOMCRYPT_SRC_FOLDER}/src/pk/asn1/der/general/der_encode_asn1_length.c 
${TOMCRYPT_SRC_FOLDER}/src/pk/asn1/der/general/der_length_asn1_identifier.c ${TOMCRYPT_SRC_FOLDER}/src/pk/asn1/der/general/der_length_asn1_length.c 
${TOMCRYPT_SRC_FOLDER}/src/pk/asn1/der/generalizedtime/der_decode_generalizedtime.c 
${TOMCRYPT_SRC_FOLDER}/src/pk/asn1/der/generalizedtime/der_encode_generalizedtime.c 
${TOMCRYPT_SRC_FOLDER}/src/pk/asn1/der/generalizedtime/der_length_generalizedtime.c 
${TOMCRYPT_SRC_FOLDER}/src/pk/asn1/der/ia5/der_decode_ia5_string.c ${TOMCRYPT_SRC_FOLDER}/src/pk/asn1/der/ia5/der_encode_ia5_string.c 
${TOMCRYPT_SRC_FOLDER}/src/pk/asn1/der/ia5/der_length_ia5_string.c ${TOMCRYPT_SRC_FOLDER}/src/pk/asn1/der/integer/der_decode_integer.c 
${TOMCRYPT_SRC_FOLDER}/src/pk/asn1/der/integer/der_encode_integer.c ${TOMCRYPT_SRC_FOLDER}/src/pk/asn1/der/integer/der_length_integer.c 
${TOMCRYPT_SRC_FOLDER}/src/pk/asn1/der/object_identifier/der_decode_object_identifier.c 
${TOMCRYPT_SRC_FOLDER}/src/pk/asn1/der/object_identifier/der_encode_object_identifier.c 
${TOMCRYPT_SRC_FOLDER}/src/pk/asn1/der/object_identifier/der_length_object_identifier.c 
${TOMCRYPT_SRC_FOLDER}/src/pk/asn1/der/octet/der_decode_octet_string.c ${TOMCRYPT_SRC_FOLDER}/src/pk/asn1/der/octet/der_encode_octet_string.c 
${TOMCRYPT_SRC_FOLDER}/src/pk/asn1/der/octet/der_length_octet_string.c 
${TOMCRYPT_SRC_FOLDER}/src/pk/asn1/der/printable_string/der_decode_printable_string.c 
${TOMCRYPT_SRC_FOLDER}/src/pk/asn1/der/printable_string/der_encode_printable_string.c 
${TOMCRYPT_SRC_FOLDER}/src/pk/asn1/der/printable_string/der_length_printable_string.c 
${TOMCRYPT_SRC_FOLDER}/src/pk/asn1/der/sequence/der_decode_sequence_ex.c 
${TOMCRYPT_SRC_FOLDER}/src/pk/asn1/der/sequence/der_decode_sequence_flexi.c 
${TOMCRYPT_SRC_FOLDER}/src/pk/asn1/der/sequence/der_decode_sequence_multi.c 
${TOMCRYPT_SRC_FOLDER}/src/pk/asn1/der/sequence/der_encode_sequence_ex.c 
${TOMCRYPT_SRC_FOLDER}/src/pk/asn1/der/sequence/der_encode_sequence_multi.c ${TOMCRYPT_SRC_FOLDER}/src/pk/asn1/der/sequence/der_length_sequence.c 
${TOMCRYPT_SRC_FOLDER}/src/pk/asn1/der/sequence/der_sequence_free.c ${TOMCRYPT_SRC_FOLDER}/src/pk/asn1/der/sequence/der_sequence_shrink.c 
${TOMCRYPT_SRC_FOLDER}/src/pk/asn1/der/set/der_encode_set.c ${TOMCRYPT_SRC_FOLDER}/src/pk/asn1/der/set/der_encode_setof.c 
${TOMCRYPT_SRC_FOLDER}/src/pk/asn1/der/short_integer/der_decode_short_integer.c 
${TOMCRYPT_SRC_FOLDER}/src/pk/asn1/der/short_integer/der_encode_short_integer.c 
${TOMCRYPT_SRC_FOLDER}/src/pk/asn1/der/short_integer/der_length_short_integer.c 
${TOMCRYPT_SRC_FOLDER}/src/pk/asn1/der/teletex_string/der_decode_teletex_string.c 
${TOMCRYPT_SRC_FOLDER}/src/pk/asn1/der/teletex_string/der_length_teletex_string.c 
${TOMCRYPT_SRC_FOLDER}/src/pk/asn1/der/utctime/der_decode_utctime.c ${TOMCRYPT_SRC_FOLDER}/src/pk/asn1/der/utctime/der_encode_utctime.c 
${TOMCRYPT_SRC_FOLDER}/src/pk/asn1/der/utctime/der_length_utctime.c ${TOMCRYPT_SRC_FOLDER}/src/pk/asn1/der/utf8/der_decode_utf8_string.c 
${TOMCRYPT_SRC_FOLDER}/src/pk/asn1/der/utf8/der_encode_utf8_string.c ${TOMCRYPT_SRC_FOLDER}/src/pk/asn1/der/utf8/der_length_utf8_string.c 
${TOMCRYPT_SRC_FOLDER}/src/pk/asn1/oid/pk_get_oid.c ${TOMCRYPT_SRC_FOLDER}/src/pk/asn1/oid/pk_oid_cmp.c ${TOMCRYPT_SRC_FOLDER}/src/pk/asn1/oid/pk_oid_str.c 
${TOMCRYPT_SRC_FOLDER}/src/pk/asn1/pkcs8/pkcs8_decode_flexi.c ${TOMCRYPT_SRC_FOLDER}/src/pk/asn1/x509/x509_decode_public_key_from_certificate.c 
${TOMCRYPT_SRC_FOLDER}/src/pk/asn1/x509/x509_decode_subject_public_key_info.c 
${TOMCRYPT_SRC_FOLDER}/src/pk/asn1/x509/x509_encode_subject_public_key_info.c ${TOMCRYPT_SRC_FOLDER}/src/pk/dh/dh.c ${TOMCRYPT_SRC_FOLDER}/src/pk/dh/dh_check_pubkey.c 
${TOMCRYPT_SRC_FOLDER}/src/pk/dh/dh_export.c ${TOMCRYPT_SRC_FOLDER}/src/pk/dh/dh_export_key.c ${TOMCRYPT_SRC_FOLDER}/src/pk/dh/dh_free.c ${TOMCRYPT_SRC_FOLDER}/src/pk/dh/dh_generate_key.c 
${TOMCRYPT_SRC_FOLDER}/src/pk/dh/dh_import.c ${TOMCRYPT_SRC_FOLDER}/src/pk/dh/dh_set.c ${TOMCRYPT_SRC_FOLDER}/src/pk/dh/dh_set_pg_dhparam.c ${TOMCRYPT_SRC_FOLDER}/src/pk/dh/dh_shared_secret.c 
${TOMCRYPT_SRC_FOLDER}/src/pk/dsa/dsa_decrypt_key.c ${TOMCRYPT_SRC_FOLDER}/src/pk/dsa/dsa_encrypt_key.c ${TOMCRYPT_SRC_FOLDER}/src/pk/dsa/dsa_export.c ${TOMCRYPT_SRC_FOLDER}/src/pk/dsa/dsa_free.c 
${TOMCRYPT_SRC_FOLDER}/src/pk/dsa/dsa_generate_key.c ${TOMCRYPT_SRC_FOLDER}/src/pk/dsa/dsa_generate_pqg.c ${TOMCRYPT_SRC_FOLDER}/src/pk/dsa/dsa_import.c 
${TOMCRYPT_SRC_FOLDER}/src/pk/dsa/dsa_make_key.c ${TOMCRYPT_SRC_FOLDER}/src/pk/dsa/dsa_set.c ${TOMCRYPT_SRC_FOLDER}/src/pk/dsa/dsa_set_pqg_dsaparam.c 
${TOMCRYPT_SRC_FOLDER}/src/pk/dsa/dsa_shared_secret.c ${TOMCRYPT_SRC_FOLDER}/src/pk/dsa/dsa_sign_hash.c ${TOMCRYPT_SRC_FOLDER}/src/pk/dsa/dsa_verify_hash.c 
${TOMCRYPT_SRC_FOLDER}/src/pk/dsa/dsa_verify_key.c ${TOMCRYPT_SRC_FOLDER}/src/pk/ec25519/ec25519_export.c ${TOMCRYPT_SRC_FOLDER}/src/pk/ec25519/ec25519_import_pkcs8.c 
${TOMCRYPT_SRC_FOLDER}/src/pk/ec25519/tweetnacl.c ${TOMCRYPT_SRC_FOLDER}/src/pk/ecc/ecc.c ${TOMCRYPT_SRC_FOLDER}/src/pk/ecc/ecc_ansi_x963_export.c 
${TOMCRYPT_SRC_FOLDER}/src/pk/ecc/ecc_ansi_x963_import.c ${TOMCRYPT_SRC_FOLDER}/src/pk/ecc/ecc_decrypt_key.c ${TOMCRYPT_SRC_FOLDER}/src/pk/ecc/ecc_encrypt_key.c 
${TOMCRYPT_SRC_FOLDER}/src/pk/ecc/ecc_export.c ${TOMCRYPT_SRC_FOLDER}/src/pk/ecc/ecc_export_openssl.c ${TOMCRYPT_SRC_FOLDER}/src/pk/ecc/ecc_find_curve.c 
${TOMCRYPT_SRC_FOLDER}/src/pk/ecc/ecc_free.c ${TOMCRYPT_SRC_FOLDER}/src/pk/ecc/ecc_get_key.c ${TOMCRYPT_SRC_FOLDER}/src/pk/ecc/ecc_get_oid_str.c ${TOMCRYPT_SRC_FOLDER}/src/pk/ecc/ecc_get_size.c 
${TOMCRYPT_SRC_FOLDER}/src/pk/ecc/ecc_import.c ${TOMCRYPT_SRC_FOLDER}/src/pk/ecc/ecc_import_openssl.c ${TOMCRYPT_SRC_FOLDER}/src/pk/ecc/ecc_import_pkcs8.c 
${TOMCRYPT_SRC_FOLDER}/src/pk/ecc/ecc_import_x509.c ${TOMCRYPT_SRC_FOLDER}/src/pk/ecc/ecc_make_key.c ${TOMCRYPT_SRC_FOLDER}/src/pk/ecc/ecc_recover_key.c 
${TOMCRYPT_SRC_FOLDER}/src/pk/ecc/ecc_set_curve.c ${TOMCRYPT_SRC_FOLDER}/src/pk/ecc/ecc_set_curve_internal.c ${TOMCRYPT_SRC_FOLDER}/src/pk/ecc/ecc_set_key.c 
${TOMCRYPT_SRC_FOLDER}/src/pk/ecc/ecc_shared_secret.c ${TOMCRYPT_SRC_FOLDER}/src/pk/ecc/ecc_sign_hash.c ${TOMCRYPT_SRC_FOLDER}/src/pk/ecc/ecc_sizes.c 
${TOMCRYPT_SRC_FOLDER}/src/pk/ecc/ecc_ssh_ecdsa_encode_name.c ${TOMCRYPT_SRC_FOLDER}/src/pk/ecc/ecc_verify_hash.c ${TOMCRYPT_SRC_FOLDER}/src/pk/ecc/ltc_ecc_export_point.c 
${TOMCRYPT_SRC_FOLDER}/src/pk/ecc/ltc_ecc_import_point.c ${TOMCRYPT_SRC_FOLDER}/src/pk/ecc/ltc_ecc_is_point.c 
${TOMCRYPT_SRC_FOLDER}/src/pk/ecc/ltc_ecc_is_point_at_infinity.c ${TOMCRYPT_SRC_FOLDER}/src/pk/ecc/ltc_ecc_map.c ${TOMCRYPT_SRC_FOLDER}/src/pk/ecc/ltc_ecc_mul2add.c 
${TOMCRYPT_SRC_FOLDER}/src/pk/ecc/ltc_ecc_mulmod.c ${TOMCRYPT_SRC_FOLDER}/src/pk/ecc/ltc_ecc_mulmod_timing.c ${TOMCRYPT_SRC_FOLDER}/src/pk/ecc/ltc_ecc_points.c 
${TOMCRYPT_SRC_FOLDER}/src/pk/ecc/ltc_ecc_projective_add_point.c ${TOMCRYPT_SRC_FOLDER}/src/pk/ecc/ltc_ecc_projective_dbl_point.c 
${TOMCRYPT_SRC_FOLDER}/src/pk/ecc/ltc_ecc_verify_key.c ${TOMCRYPT_SRC_FOLDER}/src/pk/ed25519/ed25519_export.c ${TOMCRYPT_SRC_FOLDER}/src/pk/ed25519/ed25519_import.c 
${TOMCRYPT_SRC_FOLDER}/src/pk/ed25519/ed25519_import_pkcs8.c
${TOMCRYPT_SRC_FOLDER}/src/pk/ed25519/ed25519_import_x509.c ${TOMCRYPT_SRC_FOLDER}/src/pk/ed25519/ed25519_make_key.c ${TOMCRYPT_SRC_FOLDER}/src/pk/ed25519/ed25519_sign.c 
${TOMCRYPT_SRC_FOLDER}/src/pk/ed25519/ed25519_verify.c ${TOMCRYPT_SRC_FOLDER}/src/pk/pkcs1/pkcs_1_i2osp.c ${TOMCRYPT_SRC_FOLDER}/src/pk/pkcs1/pkcs_1_mgf1.c 
${TOMCRYPT_SRC_FOLDER}/src/pk/pkcs1/pkcs_1_oaep_decode.c ${TOMCRYPT_SRC_FOLDER}/src/pk/pkcs1/pkcs_1_oaep_encode.c ${TOMCRYPT_SRC_FOLDER}/src/pk/pkcs1/pkcs_1_os2ip.c 
${TOMCRYPT_SRC_FOLDER}/src/pk/pkcs1/pkcs_1_pss_decode.c ${TOMCRYPT_SRC_FOLDER}/src/pk/pkcs1/pkcs_1_pss_encode.c ${TOMCRYPT_SRC_FOLDER}/src/pk/pkcs1/pkcs_1_v1_5_decode.c 
${TOMCRYPT_SRC_FOLDER}/src/pk/pkcs1/pkcs_1_v1_5_encode.c ${TOMCRYPT_SRC_FOLDER}/src/pk/rsa/rsa_decrypt_key.c ${TOMCRYPT_SRC_FOLDER}/src/pk/rsa/rsa_encrypt_key.c 
${TOMCRYPT_SRC_FOLDER}/src/pk/rsa/rsa_export.c ${TOMCRYPT_SRC_FOLDER}/src/pk/rsa/rsa_exptmod.c ${TOMCRYPT_SRC_FOLDER}/src/pk/rsa/rsa_get_size.c ${TOMCRYPT_SRC_FOLDER}/src/pk/rsa/rsa_import.c 
${TOMCRYPT_SRC_FOLDER}/src/pk/rsa/rsa_import_pkcs8.c ${TOMCRYPT_SRC_FOLDER}/src/pk/rsa/rsa_import_x509.c  
${TOMCRYPT_SRC_FOLDER}/src/pk/rsa/rsa_make_key.c ${TOMCRYPT_SRC_FOLDER}/src/pk/rsa/rsa_set.c ${TOMCRYPT_SRC_FOLDER}/src/pk/rsa/rsa_sign_hash.c 
${TOMCRYPT_SRC_FOLDER}/src/pk/rsa/rsa_sign_saltlen_get.c ${TOMCRYPT_SRC_FOLDER}/src/pk/rsa/rsa_verify_hash.c ${TOMCRYPT_SRC_FOLDER}/src/pk/x25519/x25519_export.c 
${TOMCRYPT_SRC_FOLDER}/src/pk/x25519/x25519_import.c ${TOMCRYPT_SRC_FOLDER}/src/pk/x25519/x25519_import_pkcs8.c 
${TOMCRYPT_SRC_FOLDER}/src/pk/x25519/x25519_import_x509.c ${TOMCRYPT_SRC_FOLDER}/src/pk/x25519/x25519_make_key.c 
${TOMCRYPT_SRC_FOLDER}/src/pk/x25519/x25519_shared_secret.c ${TOMCRYPT_SRC_FOLDER}/src/prngs/chacha20.c ${TOMCRYPT_SRC_FOLDER}/src/prngs/fortuna.c ${TOMCRYPT_SRC_FOLDER}/src/prngs/rc4.c 
${TOMCRYPT_SRC_FOLDER}/src/prngs/rng_get_bytes.c ${TOMCRYPT_SRC_FOLDER}/src/prngs/rng_make_prng.c ${TOMCRYPT_SRC_FOLDER}/src/prngs/sober128.c ${TOMCRYPT_SRC_FOLDER}/src/prngs/sprng.c 
${TOMCRYPT_SRC_FOLDER}/src/prngs/yarrow.c ${TOMCRYPT_SRC_FOLDER}/src/stream/chacha/chacha_crypt.c ${TOMCRYPT_SRC_FOLDER}/src/stream/chacha/chacha_done.c 
${TOMCRYPT_SRC_FOLDER}/src/stream/chacha/chacha_ivctr32.c ${TOMCRYPT_SRC_FOLDER}/src/stream/chacha/chacha_ivctr64.c 
${TOMCRYPT_SRC_FOLDER}/src/stream/chacha/chacha_keystream.c ${TOMCRYPT_SRC_FOLDER}/src/stream/chacha/chacha_memory.c 
${TOMCRYPT_SRC_FOLDER}/src/stream/chacha/chacha_setup.c ${TOMCRYPT_SRC_FOLDER}/src/stream/chacha/chacha_test.c ${TOMCRYPT_SRC_FOLDER}/src/stream/rabbit/rabbit.c 
${TOMCRYPT_SRC_FOLDER}/src/stream/rabbit/rabbit_memory.c ${TOMCRYPT_SRC_FOLDER}/src/stream/rc4/rc4_stream.c ${TOMCRYPT_SRC_FOLDER}/src/stream/rc4/rc4_stream_memory.c 
${TOMCRYPT_SRC_FOLDER}/src/stream/rc4/rc4_test.c ${TOMCRYPT_SRC_FOLDER}/src/stream/salsa20/salsa20_crypt.c ${TOMCRYPT_SRC_FOLDER}/src/stream/salsa20/salsa20_done.c 
${TOMCRYPT_SRC_FOLDER}/src/stream/salsa20/salsa20_ivctr64.c ${TOMCRYPT_SRC_FOLDER}/src/stream/salsa20/salsa20_keystream.c 
${TOMCRYPT_SRC_FOLDER}/src/stream/salsa20/salsa20_memory.c ${TOMCRYPT_SRC_FOLDER}/src/stream/salsa20/salsa20_setup.c 
${TOMCRYPT_SRC_FOLDER}/src/stream/salsa20/salsa20_test.c ${TOMCRYPT_SRC_FOLDER}/src/stream/salsa20/xsalsa20_memory.c 
${TOMCRYPT_SRC_FOLDER}/src/stream/salsa20/xsalsa20_setup.c ${TOMCRYPT_SRC_FOLDER}/src/stream/salsa20/xsalsa20_test.c 
${TOMCRYPT_SRC_FOLDER}/src/stream/sober128/sober128_stream.c ${TOMCRYPT_SRC_FOLDER}/src/stream/sober128/sober128_stream_memory.c 
${TOMCRYPT_SRC_FOLDER}/src/stream/sober128/sober128_test.c ${TOMCRYPT_SRC_FOLDER}/src/stream/sosemanuk/sosemanuk.c 
${TOMCRYPT_SRC_FOLDER}/src/stream/sosemanuk/sosemanuk_memory.c ${TOMCRYPT_SRC_FOLDER}/src/stream/sosemanuk/sosemanuk_test.c

#These are not included in older version of libtomcrypt
#${TOMCRYPT_SRC_FOLDER}/src/pk/rsa/rsa_key.c
#${TOMCRYPT_SRC_FOLDER}/src/pk/ed25519/ed25519_import_raw.c 
#${TOMCRYPT_SRC_FOLDER}/src/ciphers/tea.c
#${TOMCRYPT_SRC_FOLDER}/src/misc/bcrypt/bcrypt.c 
#${TOMCRYPT_SRC_FOLDER}/src/pk/x25519/x25519_import_raw.c 
)

list(APPEND tomcrypt_include_dirs
    "${TOMCRYPT_SRC_FOLDER}/src/headers"
    "${TOMMATH_SRC_FOLDER}"
    "${OPTEE_SRC_FOLDER}/lib/libutils/ext/include"
    "include"
)

target_include_directories(tomcrypt
PUBLIC
    ${tomcrypt_include_dirs}
)  


target_compile_definitions(tomcrypt PUBLIC
 #USE_LTM
 #LTM_DESC
 MP_YES=true
 MP_NO=false
 LTC_MAX_ECC=521
 )

target_link_libraries(tomcrypt
    PUBLIC
        muslc
        sel4
        sel4runtime
        sel4utils
        sel4platsupport
        sel4_autoconf
    PRIVATE
        teeos_Config
        tommath
)

export(PACKAGE ${PROJECT_NAME})
