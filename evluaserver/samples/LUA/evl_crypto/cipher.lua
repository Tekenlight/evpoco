local ffi = require('ffi');
ffi.cdef[[
void * pin_loaded_so(const char * libname);
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

local status, symmetric_key = pcall(evl_crypto.generate_aes_key, 256);
if (not status) then
	error(symmetric_key);
end

local plain_text = "Hello World";

local status, ct, len = pcall(evl_crypto.encrypt_text, plain_text, symmetric_key);
if (not status) then
	error(ct);
end

print(debug.getinfo(1).source, debug.getinfo(1).currentline);
print(ct);
print(len);
print(debug.getinfo(1).source, debug.getinfo(1).currentline);

local status, pt = pcall(evl_crypto.decrypt_cipher_text, ct, symmetric_key);
if (not status) then
	error(pt);
end
print(debug.getinfo(1).source, debug.getinfo(1).currentline);
print(pt);
print(debug.getinfo(1).source, debug.getinfo(1).currentline);
