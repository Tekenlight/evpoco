local crypto_utils = require('service_utils.crypto.crypto_utils');



local rsa_key_pair = crypto_utils.form_rsa_key_pair(1024);

local pub_key = rsa_key_pair.pub_key;
local prv_key = rsa_key_pair.prv_key;

local rsa_pub_key = crypto_utils.form_rsa_key_from_public_key(pub_key);
local rsa_prv_key = crypto_utils.form_rsa_key_from_private_key(prv_key);

print(pub_key == crypto_utils.get_rsa_public_key(rsa_pub_key));
print(prv_key == crypto_utils.get_rsa_private_key(rsa_prv_key));

local plain_text = [[<?xml version="1.0" encoding="UTF-8"?>
<ns1:test_message xmlns:ns1="http://xchange_messages.biop.com">
  <greeting>Hello World</greeting>
</ns1:test_message>]]

--local symmetric_key = crypto_utils.generate_aes_key(256);
local symmetric_key = crypto_utils.generate_symmetric_key("aes-256-cbc");

local ct, len = crypto_utils.encrypt_plain_text(plain_text, symmetric_key);
local pt = crypto_utils.decrypt_cipher_text(ct, symmetric_key);

local b64_ct = crypto_utils.b64_encrypt_plain_text(plain_text, symmetric_key);

local e_symm_key = crypto_utils.rsa_encrypt_symmetric_key(symmetric_key, rsa_pub_key);

local b64_e_symm_key = crypto_utils.rsa_b64_encrypt_symmetric_key(symmetric_key, rsa_pub_key);

--===============================================================================--

local tc1_o_symm_key = crypto_utils.rsa_decrypt_b64_enc_symmetric_key(b64_e_symm_key, rsa_prv_key);

local tc2_o_symm_key = crypto_utils.rsa_decrypt_enc_symmetric_key(e_symm_key, rsa_prv_key);

local pt = crypto_utils.decrypt_b64_cipher_text(b64_ct, tc1_o_symm_key);
print(pt);
print(pt == plain_text);


local pt = crypto_utils.decrypt_cipher_text(ct, tc2_o_symm_key);

print(pt);
print(pt == plain_text);



