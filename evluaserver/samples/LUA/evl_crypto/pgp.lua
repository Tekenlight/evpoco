local ffi = require('ffi');
local cu = require('lua_schema.core_utils');

ffi.cdef[[
void * pin_loaded_so(const char * libname);
struct cipher_text_s {
    unsigned char * buffer;
    size_t len;
};
]]

local evl_crypto_loader = package.loadlib('libevlcrypto.so','luaopen_libevlcrypto');
local loaded, evl_crypto = pcall(evl_crypto_loader);
if(not loaded) then
    error("Could not load library: "..evl_crypto);
end
local loaded, lib = pcall(ffi.C.pin_loaded_so, 'libevlcrypto.so');
if(not loaded) then
    error("Could not load library: "..evl_crypto);
end








local status, rsa_key_pair = pcall(evl_crypto.generate_rsa_key_pair, 1024);
if (not status) then
	error(rsa_key_pair);
end

--print(evl_crypto.get_rsa_public_key(rsa_key_pair));
--print(evl_crypto.get_rsa_private_key(rsa_key_pair));

local pub_key = evl_crypto.get_rsa_public_key(rsa_key_pair);
local prv_key = evl_crypto.get_rsa_private_key(rsa_key_pair);

local rsa_pub_key = evl_crypto.load_rsa_public_key(pub_key);
local rsa_prv_key = evl_crypto.load_rsa_private_key(prv_key);

print(pub_key == evl_crypto.get_rsa_public_key(rsa_pub_key));
print(prv_key == evl_crypto.get_rsa_private_key(rsa_prv_key));

local plain_text = "Hello World";

local status, symmetric_key = pcall(evl_crypto.generate_aes_key, 256);
if (not status) then
	error(symmetric_key);
end

local status, ct, len, bp = pcall(evl_crypto.encrypt_text, plain_text, symmetric_key);
if (not status) then
	error(ct);
end

print(debug.getinfo(1).source, debug.getinfo(1).currentline, type(symmetric_key));

local ct_s = ffi.new("hex_data_s_type", 0);
local ctp = ffi.cast("cipher_text_s*", ct);
ct_s.value = ctp.buffer;
ct_s.size = ctp.len;
local b64_ct = cu.base64_encode(ct_s);
ct_s.value = ffi.NULL; -- In order to overcome freeing of pointers twice

local status, e_symm_key = pcall(evl_crypto.rsa_encrypt_symm_key, symmetric_key, rsa_pub_key);
if (not status) then
	error(e_symm_key);
end

ctp = ffi.cast("cipher_text_s*", e_symm_key);
ct_s.value = ctp.buffer;
ct_s.size = ctp.len;
local b64_e_symm_key = cu.base64_encode(ct_s);
ct_s.value = ffi.NULL; -- In order to overcome freeing of pointers twice
--===============================================================================--

local status, o_symm_key = pcall(evl_crypto.rsa_decrypt_b64_enc_symm_key, b64_e_symm_key, rsa_prv_key);
if (not status) then
	error(o_symm_key);
end

local status, pt = pcall(evl_crypto.decrypt_b64_cipher_text, b64_ct, len, o_symm_key);
if (not status) then
	error(pt);
end

print(pt);
print(pt == plain_text);



