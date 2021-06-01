"""List of TA and TEE syscall declarations."""

import tsmok.optee.syscall_parser as parser

TA_SYSCALL_DECLARATIONS = """
"open_session" 0 ("sid" int32 [ __out_res__ ], "param" optee_ta_param_ptr) void
"invoke_command" 2 ("sid" int32 [ __in_res__ ], "param" optee_ta_param_ptr, "cmd" int32) void
"close_session" 1 ("sid" int32 [ __in_res__ ]) void
"""

TEE_SYSCALL_DECLARATIONS = """
"sys_return" 0 ("ret" int32) void
"log" 1 ("buf" void_ptr, "len" int32) void
"panic" 2 ("code" int32) void
"get_property" 3 ("prop_set" int32, "index" int32, "name" void_ptr, "name_len" int32_ptr, "buf" void_ptr, "blen" int32_ptr, "prop_type" int32_ptr) int32
"get_property_name_to_index" 4 ("prop_set" int32, "name" void_ptr, "name_len" int32, "index" int32_ptr) int32
"open_ta_session" 5 (TEE_UUID *dest, "cancel_req_to" int32, struct utee_params *usr_param, "ta_sess" int32_ptr, "ret_orig" int32_ptr) int32
"close_ta_session" 6 ("ta_sess" int32) int32
"invoke_ta_command" 7 ("ta_sess" int32, "cancel_req_to" int32, "cmd_id" int32, struct utee_params *usr_param, "ret_orig" int32_ptr) int32
"check_access_rights" 8 ("flags" int32, "buf" void_ptr, "len" int32) int32
"get_cancellation_flag" 9 ("cancel" int32_ptr) int32
"unmask_cancellation" 10 ("old_mask" int32_ptr) int32;
"mask_cancellation" 11 ("old_mask" int32_ptr) int32;
"wait" 12 ("timeout" int32) int32;
"get_time" 13 ("cat" int32, TEE_Time *time) int32;
"set_ta_time" 14 (TEE_Time *mytime) int32
"cryp_state_alloc" 15 ("algo" int32, "mode" int32, "key1" int32, "key2" int32, "state" int32_ptr) int32
"cryp_state_copy" 16 ("dst" int32, "src" int32) int32
"cryp_state_free" 17 ("state" int32) int32
"hash_init" 18 ("state" int32, "iv" void_ptr, "iv_len" int32) int32
"hash_update" 19 ("state" int32, "chunk" void_ptr, "chunk_size" int32) int32
"hash_final" 20 ("state" int32, "chunk" void_ptr, "chunk_size" int32, "hash" void_ptr, "hash_len" int64_ptr) int32
"cipher_init" 21 ("state" int32, "iv" void_ptr, "iv_len" int32) int32
"cipher_update" 22 ("state" int32, "src" void_ptr, "src_len" int32, "dst" void_ptr, "dst_len" int64_ptr) int32
"cipher_final" 23 ("state" int32, "src" void_ptr, "src_len" int32, "dst" void_ptr, "dst_len" int64_ptr) int32
"cryp_obj_get_info" 24 ("obj" int32, TEE_ObjectInfo *info) int32
"cryp_obj_restrict_usage" 25 ("obj" int32, "usage" int32) int32
"cryp_obj_get_attr" 26 ("obj" int32, "attr_id" int32, "buffer" void_ptr, "size" int64_ptr) int32
"cryp_obj_alloc" 27 ("obj_type" int32, "max_key_size" int32, "obj" int32_ptr) int32
"cryp_obj_close" 28 ("obj" int32) int32
"cryp_obj_reset" 29 ("obj" int32) int32
"cryp_obj_populate" 30 ("obj" int32, struct utee_attribute *usr_attrs, "attr_count" int32) int32
"cryp_obj_copy" 31 ("dst" int32, "src" int32) int32
"cryp_derive_key" 32 ("state" int32, struct utee_attribute *usr_params, "param_count" int32, "derived_key" int32) int32
"cryp_random_number_generate" 33 ("buf" void_ptr, "blen" int32) int32
"authenc_init" 34 ("state" int32, "nonce" void_ptr, "nonce_len" int32, "tag_len" int32, "aad_len" int32, "payload_len" int32) int32
"authenc_update_aad" 35 ("state" int32, "aad_data" void_ptr, "aad_data_len" int32) int32
"authenc_update_payload" 36 ("state" int32, "src_data" void_ptr, "src_len" int32, "dst_data" void_ptr, "dst_len" int64_ptr) int32
"authenc_enc_final" 37 ("state" int32, "src_data" void_ptr, "src_len" int32, "dst_data" void_ptr, "dst_len" int64_ptr, "tag" void_ptr, "tag_len" int64_ptr) int32
"authenc_dec_final" 38 ("state" int32, "src_data" void_ptr, "src_len" int32, "dst_data" void_ptr, "dst_len" int64_ptr, "tag" void_ptr, "tag_len" int32) int32
"asymm_operate" 39 ("state" int32, struct utee_attribute *usr_params, "num_params" int32, "src_data" void_ptr, "src_len" int32, "dst_data" void_ptr, "dst_len" int64_ptr) int32
"asymm_verify" 40 ("state" int32, struct utee_attribute *usr_params, "num_params" int32, "data" void_ptr, "data_len" int32, "sig" void_ptr, "sig_len" int32) int32
"storage_obj_open" 41 ("storage_id" int32, "object_id" void_ptr, "object_id_len" int32, "flags" int32, "obj" int32_ptr) int32
"storage_obj_create" 42 ("storage_id" int32, "object_id" void_ptr, "object_id_len" int32, "flags" int32, "attr" int32, "data" void_ptr, "len" int32, "obj" int32_ptr) int32
"storage_obj_del" 43 ("obj" int32) int32
"storage_obj_rename" 44 ("obj" int32, "object_id" void_ptr, "object_id_len" int32) int32
"storage_alloc_enum" 45 ("obj_enum" int32_ptr) int32
"storage_free_enum" 46 ("obj_enum" int32) int32
"storage_reset_enum" 47 ("obj_enum" int32) int32
"storage_start_enum" 48 ("obj_enum" int32, "storage_id" int32) int32
"storage_next_enum" 49 ("obj_enum" int32, TEE_ObjectInfo *info, "obj_id" void_ptr, "len" int64_ptr) int32
"storage_obj_read" 50 ("obj" int32, "data" void_ptr, "len" int32, "count" int64_ptr) int32
"storage_obj_write" 51 ("obj" int32, "data" void_ptr, "len" int32) int32
"storage_obj_trunc" 52 ("obj" int32, "len" int32) int32
"storage_obj_seek" 53 ("obj" int32, "offset" int32_t, "whence" int32) int32
"obj_generate_key" 54 ("obj" int32, "key_size" int32, struct utee_attribute *usr_params, "param_count" int32) int32
"cache_operation" 70 ("va" void_ptr, "len" int32, "op" int32) int32
"""

TA_SYSCALLS = dict()

TEE_SYSCALLS = dict()


def ta_syscall_types():
  if not TA_SYSCALLS:
    for line in TA_SYSCALL_DECLARATIONS.splitlines():
      if line:
        call = parser.parse(line)
        TA_SYSCALLS[call.NR] = call

  return TA_SYSCALLS


def tee_syscall_types():
  if not TEE_SYSCALLS:
    for line in TEE_SYSCALL_DECLARATIONS.splitlines():
      if line:
        call = parser.parse(line)
        TEE_SYSCALLS[call.NR] = call

  return TEE_SYSCALLS
