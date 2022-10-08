local crypto_utils = require('service_utils.crypto.crypto_utils');
local core_utils = require('lua_schema.core_utils');



local rsa_key_pair = crypto_utils.form_rsa_key_pair(1024);

local pub_key = rsa_key_pair.pub_key;
local prv_key = rsa_key_pair.prv_key;

local rsa_pub_key = crypto_utils.form_rsa_key_from_public_key(pub_key);
local rsa_prv_key = crypto_utils.form_rsa_key_from_private_key(prv_key);

local plain_text = [[<?xml version="1.0" encoding="UTF-8"?>
<ns1:test_message xmlns:ns1="http://xchange_messages.biop.com">
  <greeting>Hello World</greeting>
</ns1:test_message>]]

--local symmetric_key = crypto_utils.generate_aes_key(256);
local symmetric_key = crypto_utils.generate_symmetric_key("aes-256-cbc");

local ct, len, ct_s  = crypto_utils.encrypt_plain_text(plain_text, symmetric_key);
local b64_ct = core_utils.base64_encode(ct_s);

local e_symm_key, len, e_symm_key_s = crypto_utils.rsa_encrypt_symmetric_key(symmetric_key, rsa_pub_key);
local b64_enc_enc_key = core_utils.base64_encode(e_symm_key_s);

--===============================================================================--

local r_enc_enc_key = core_utils.base64_decode(b64_enc_enc_key);
local r_ct = core_utils.base64_decode(b64_ct);

local o_symm_key = crypto_utils.rsa_decrypt_hex_s_enc_symmetric_key(r_enc_enc_key, rsa_prv_key);
local pt = crypto_utils.decrypt_hex_s_cipher_text(r_ct, o_symm_key);

print(pt);
print(pt == plain_text);




