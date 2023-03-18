local ffi = require('ffi');
local evl_crypto  = (require('service_utils.common.utils')).load_library('libevlcrypto');

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
