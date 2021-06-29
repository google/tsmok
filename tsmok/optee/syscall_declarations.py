"""List of TA and TEE syscall declarations."""

import tsmok.optee.syscall_parser as parser

TA_SYSCALL_DECLARATIONS = """
"open_session" 0 ("sid" int32 [ __out_res__ ], "param" utee_param_ptr [ __out__ ]) void
"invoke_command" 2 ("sid" int32 [ __in_res__ ], "param" utee_param_ptr [ __out__ ], "cmd" int32) void
"close_session" 1 ("sid" int32 [ __in_res__ ]) void
"""

TEE_SYSCALL_DECLARATIONS = """
"log" 1 ("buf" void_ptr [__array__], "len" int32 [__array_len__]) void
"get_property" 3 ("prop_set" int32, "index" int32 [ __in_res__ ], "name" void_ptr [ __array__ ], "name_len" int32_ptr [ __array_len__], "buf" void_ptr [ __array__ ], "buf_len" int32_ptr [ __array_len__ ], "prop_type" int32_ptr) int32
"get_property_name_to_index" 4 ("prop_set" int32, "name" void_ptr [ __array__ ], "name_len" int32 [ __array_len__ ], "index" int32_ptr [ __out_res__ ]) int32
"open_ta_session" 5 ("uuid_dest" uuid_ptr, "cancel_req_to" int32, "param" utee_param_ptr, "ta_sess" int32_ptr [ __out_res__ ], "ret_orig" int32_ptr) int32
"close_ta_session" 6 ("ta_sess" int32 [ __in_res__ ]) int32
"invoke_ta_command" 7 ("ta_sess" int32 [ __in_res__ ], "cancel_req_to" int32, "cmd_id" int32, "param" utee_param_ptr, "ret_orig" int32_ptr) int32
"check_access_rights" 8 ("flags" int32, "buf" void_ptr [ __array__ ], "buf_len" int32 [ __array_len__ ]) int32
"get_cancellation_flag" 9 ("cancel" int32_ptr) int32
"unmask_cancellation" 10 ("old_mask" int32_ptr) int32
"mask_cancellation" 11 ("old_mask" int32_ptr) int32
"wait" 12 ("timeout" int32) int32
"get_time" 13 ("cat" int32, "time" time_ptr) int32
"set_ta_time" 14 ("time" time_ptr) int32
"cryp_state_alloc" 15 ("algo" int32, "mode" int32, "key1" int32, "key2" int32, "state" int32_ptr [ __out_res__ ]) int32
"cryp_state_copy" 16 ("dst" int32 [ __in_res__ ], "src" int32 [ __in_res__ ]) int32
"cryp_state_free" 17 ("state" int32 [ __in_res__ ]) int32
"hash_init" 18 ("state" int32 [ __in_res__ ], "iv" void_ptr [ __array__ ], "iv_len" int32 [ __array_len__ ]) int32
"hash_update" 19 ("state" int32 [ __in_res__ ], "chunk" void_ptr [ __array__ ], "chunk_len" int32 [ __array_len__ ]) int32
"hash_final" 20 ("state" int32 [ __in_res__ ], "chunk" void_ptr [ __array__ ], "chunk_len" int32 [ __array_len__ ], "hash" void_ptr [ __array__ ], "hash_len" int64_ptr [ __array_len__ ]) int32
"cipher_init" 21 ("state" int32 [ __in_res__ ], "iv" void_ptr [ __array__ ], "iv_len" int32 [ __array_len__ ]) int32
"cipher_update" 22 ("state" int32 [ __in_res__ ], "src" void_ptr [ __array__ ], "src_len" int32 [ __array_len__ ], "dst" void_ptr [ __array__ ], "dst_len" int64_ptr [ __array_len__ ]) int32
"cipher_final" 23 ("state" int32 [ __in_res__ ], "src" void_ptr [ __array__ ], "src_len" int32 [ __array_len__ ], "dst" void_ptr [ __array__ ], "dst_len" int64_ptr [ __array_len__ ]) int32
"cryp_obj_get_info" 24 ("obj" int32 [ __in_res__ ], "object_info" void_ptr) int32
"cryp_obj_restrict_usage" 25 ("obj" int32 [ __in_res__ ], "usage" int32) int32
"cryp_obj_get_attr" 26 ("obj" int32 [ __in_res__ ], "attr_id" int32, "buf" void_ptr [ __array__ ], "buf_len" int64_ptr [ __array_len__ ]) int32
"cryp_obj_alloc" 27 ("obj_type" int32, "max_key_size" int32, "obj" int32_ptr [ __out_res__ ]) int32
"cryp_obj_close" 28 ("obj" int32 [ __in_res__ ]) int32
"cryp_obj_reset" 29 ("obj" int32 [ __in_res__ ]) int32
"cryp_obj_populate" 30 ("obj" int32 [ __in_res__ ], "attrs" utee_attribute_ptr [ __array__ ], "attrs_count" int32 [ __array_len__ ]) int32
"cryp_obj_copy" 31 ("dst" int32 [ __in_res__ ], "src" int32 [ __in_res__ ]) int32
"cryp_derive_key" 32 ("state" int32 [ __in_res__ ], "params" utee_attribute_ptr [ __array__ ], "params_len" int32 [ __array_len__ ], "derived_key" int32) int32
"cryp_random_number_generate" 33 ("buf" void_ptr [ __array__ ], "buf_len" int32 [ __array_len__ ]) int32
"authenc_init" 34 ("state" int32 [ __in_res__ ], "nonce" void_ptr [ __array__ ], "nonce_len" int32 [ __array_len__ ], "tag_len" int32, "aad_len" int32, "payload_len" int32) int32
"authenc_update_aad" 35 ("state" int32 [ __in_res__ ], "aad" void_ptr [ __array__ ], "aad_len" int32 [ __array_len__ ]) int32
"authenc_update_payload" 36 ("state" int32 [ __in_res__ ], "src" void_ptr [ __array__ ], "src_len" int32 [ __array_len__ ], "dst" void_ptr [ __array__ ], "dst_len" int64_ptr [ __array_len__ ]) int32
"authenc_enc_final" 37 ("state" int32 [ __in_res__ ], "src" void_ptr [ __array__ ], "src_len" int32 [ __array_len__ ], "dst" void_ptr [ __array__ ], "dst_len" int64_ptr [ __array_len__ ], "tag" void_ptr [ __array__ ], "tag_len" int64_ptr [ __array_len__ ]) int32
"authenc_dec_final" 38 ("state" int32 [ __in_res__ ], "src" void_ptr [ __array__ ], "src_len" int32 [ __array_len__ ], "dst" void_ptr [ __array__ ], "dst_len" int64_ptr [ __array_len__ ], "tag" void_ptr [ __array__ ], "tag_len" int32 [__array_len__ ]) int32
"asymm_operate" 39 ("state" int32 [ __in_res__ ], "params" utee_attribute_ptr [ __array__ ], "params_len" int32 [ __array_len__ ], "src" void_ptr [ __array__ ], "src_len" int32 [ __array_len__ ], "dst" void_ptr [ __array__ ], "dst_len" int64_ptr [ __array_len__ ]) int32
"asymm_verify" 40 ("state" int32 [ __in_res__ ], "params" utee_attribute_ptr [ __array__ ], "params_len" int32 [ __array_len__ ], "data" void_ptr [ __array__ ], "data_len" int32 [ __array_len__ ], "sig" void_ptr [ __array__ ], "sig_len" int32 [ __array_len__ ]) int32
"storage_obj_open" 41 ("storage_id" int32, "object_id" void_ptr [ __array__ ], "object_id_len" int32 [ __array_len__ ], "flags" int32, "obj" int32_ptr [ __out_res__ ]) int32
"storage_obj_create" 42 ("storage_id" int32, "object_id" void_ptr [ __array__ ], "object_id_len" int32 [ __array_len__ ], "flags" int32, "attr" int32, "data" void_ptr [ __array__ ], "data_len" int32 [ __array_len__ ], "obj" int32_ptr [ __out_res__ ]) int32
"storage_obj_del" 43 ("obj" int32 [ __in_res__ ]) int32
"storage_obj_rename" 44 ("obj" int32 [ __in_res__ ], "object_id" void_ptr [ __array__ ], "object_id_len" int32 [ __array_len__ ]) int32
"storage_alloc_enum" 45 ("obj_enum" int32_ptr [ __out_res__ ]) int32
"storage_free_enum" 46 ("obj_enum" int32 [ __in_res__ ]) int32
"storage_reset_enum" 47 ("obj_enum" int32 [ __in_res__ ]) int32
"storage_start_enum" 48 ("obj_enum" int32 [ __in_res__ ], "storage_id" int32) int32
"storage_next_enum" 49 ("obj_enum" int32 [ __in_res__ ], "info" void_ptr, "obj_id" void_ptr [__array__], "obj_id_len" int64_ptr [__array_len__]) int32
"storage_obj_read" 50 ("obj" int32 [ __in_res__], "data" void_ptr [ __array__ ], "data_len" int32 [ __array_len__], "count" int64_ptr) int32
"storage_obj_write" 51 ("obj" int32 [ __in_res__ ], "data" void_ptr [ __array__ ], "data_len" int32 [ __array_len__ ]) int32
"storage_obj_trunc" 52 ("obj" int32 [ __in_res__ ], "len" int32) int32
"storage_obj_seek" 53 ("obj" int32 [ __in_res__ ], "offset" int32, "whence" int32) int32
"obj_generate_key" 54 ("obj" int32 [ __in_res__ ], "key_size" int32, "params" utee_attribute_ptr [ __array__ ], "param_len" int32 [ __array_len__ ]) int32
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
