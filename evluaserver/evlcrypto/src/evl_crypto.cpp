#include <string.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <stddef.h>
#include <assert.h>

extern "C" {
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include <string.h>
}

#include <sstream>

#include <ev_buffered_stream.h>

#include "Poco/Crypto/DigestEngine.h"
#include "Poco/Crypto/CipherFactory.h"
#include "Poco/Crypto/Cipher.h"
#include "Poco/Crypto/CipherKey.h"
#include "Poco/MemoryStream.h"

#ifdef DEBUGPOINT
#undef DEBUGPOINT
#endif
#ifdef __linux__
#define DEBUGPOINT(...) { \
	char filename[512]; \
	char *fpath; \
	fflush(stdout); \
	strcpy(filename, __FILE__); \
    fpath = basename(filename); printf("[%p][%s:%d] Reached:",(void*)pthread_self(), fpath, __LINE__); \
    printf(__VA_ARGS__);fflush(stdout); fflush(stdout); \
}
#else
#include <libgen.h>
#define DEBUGPOINT(...) { \
	char fpath[256]; \
	fflush(stdout); \
    basename_r(__FILE__,fpath); printf("[%p][%s:%d] Reached:",(void*)pthread_self(), fpath, __LINE__); \
    printf(__VA_ARGS__);fflush(stdout); fflush(stdout); \
}
#endif

using namespace Poco::Crypto;


static int hmac_fdigest(lua_State *L)
{
    const char *t = luaL_checkstring(L, 1);
    const EVP_MD *type = EVP_get_digestbyname(t);
    size_t slen; const char *s;
    size_t klen; const char *k;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int written = 0;

	memset(digest, 0, EVP_MAX_MD_SIZE);

    if (type == NULL) {
        luaL_argerror(L, 1, "invalid digest type");
        return 0;
    }

    s = luaL_checklstring(L, 2, &slen);
    k = luaL_checklstring(L, 3, &klen);


	/*
    //HMAC_CTX_init(&c);
    HMAC_CTX * c = HMAC_CTX_new();
	HMAC_CTX_reset(c);
    HMAC_Init_ex(c, k, klen, type, NULL);
    HMAC_Update(c, (unsigned char *)s, slen);
    HMAC_Final(c, digest, &written);
    //HMAC_CTX_cleanup(c);
	HMAC_CTX_free(c);
	*/

	/*
	 * Reference for the below code is 
	 * man EVP_MAC_CTX_new, example in the end of the man page
	 *
	 * There seems to be abother implementation possible in
	 * Ref: https://stackoverflow.com/questions/12545811/using-hmac-vs-evp-functions-in-openssl
	 */
	EVP_MAC *mac = EVP_MAC_fetch(NULL, "hmac", NULL);
	EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
	OSSL_PARAM params[3];
	params[0] = OSSL_PARAM_construct_utf8_string("digest", (char*)t, 0);
	params[1] = OSSL_PARAM_construct_end();
	EVP_MAC_init(ctx, (const unsigned char *)k, klen, params);
	EVP_MAC_update(ctx, (const unsigned char *)s, slen);
	EVP_MAC_final(ctx, (unsigned char*)digest, (unsigned long *)(&written), EVP_MAX_MD_SIZE);
	EVP_MAC_CTX_free(ctx);
	EVP_MAC_free(mac);

    if (lua_toboolean(L, 4)) {
        lua_pushlstring(L, (char *)digest, written);
	}
    else {
        char * hex = (char *)calloc(sizeof(char), written * 2 + 1);
        for (unsigned int i = 0; i < written; i++)
            sprintf(hex + 2 * i, "%02x", digest[i]);
        lua_pushlstring(L, hex, written * 2);
        free(hex);
    }

    return 1;
}


static int generate_hash(lua_State *L, const char * algo)
{
	const char * inp_str = lua_tostring(L, 1);
	if (inp_str == NULL) {
		lua_pushnil(L);
		lua_pushstring(L, "s_hash(s, salt): Input string manadatory");
		return 2;

	}
	const char * salt = luaL_tolstring(L, 2, NULL);
	size_t len = strlen(inp_str) + ((salt)?strlen(salt):0);
	char * str = (char*)malloc(len+1);
	strcpy(str, inp_str);
	if (salt) strcat(str, salt);

	DigestEngine d(algo);
	d.update((const void *)str, len);

	std::string digest = d.digestToHex(d.digest());


	lua_pushstring(L, digest.c_str());

	free(str);
	return 1;
}

static int generate_hash_from_string_sha1(lua_State *L)
{
	return generate_hash(L, "SHA1");
}

static int generate_hash_from_string_sha256(lua_State *L)
{
	return generate_hash(L, "SHA256");
}

static int generate_hash_from_string_sha384(lua_State *L)
{
	return generate_hash(L, "SHA384");
}

static int generate_hash_from_string_sha512(lua_State *L)
{
	return generate_hash(L, "SHA512");
}

static const luaL_Reg _lib[] = {
	{ NULL, NULL }
};

struct cipher_text_s {
	void * buffer;
	size_t len;
};

const static char *_cipher_text_name = "cipher_text";
static int cipher_text__gc(lua_State *L)
{
	//struct cipher_text_s * ptr = (cipher_text_s *)luaL_checkudata(L, 1, _cipher_text_name);
	//free(ptr->buffer);
	char * ptr = *(char **)luaL_checkudata(L, 1, _cipher_text_name);
	if (!ptr) DEBUGPOINT("ptr = [%p]\n", ptr);
	if (ptr) free(ptr);
	return 0;
}

static int cipher_text__tostring(lua_State *L)
{
	//struct cipher_text_s * ptr = (cipher_text_s *)luaL_checkudata(L, 1, _cipher_text_name);
	char * ptr = *(char **)luaL_checkudata(L, 1, _cipher_text_name);
	lua_pushfstring(L, "%s:%p", _cipher_text_name, ptr);
	return 1;
}

const static char *_cipher_key_name = "cipher_key";
static int cipher_key__gc(lua_State *L)
{
	CipherKey * ptr = *(CipherKey **)luaL_checkudata(L, 1, _cipher_key_name);
	delete ptr;
	return 0;
}

static int cipher_key__tostring(lua_State *L)
{
	CipherKey * ptr = *(CipherKey **)luaL_checkudata(L, 1, _cipher_key_name);
	lua_pushfstring(L, "%s:%p", _cipher_key_name, ptr);
	return 1;
}

static int generate_aes_key(lua_State *L)
{
	int key_length = luaL_checkinteger(L, 1);
	switch(key_length) {
		case 128:
		case 192:
		case 256:
			break;
		default:
			luaL_error(L, "Invalid key length, must be one of (128, 192 or 256)");
			return 0;
	}
	char name[128] = {'\0'};
	sprintf(name, "aes-%d-cbc", key_length);

	CipherKey *key = NULL;
	try {
		key = new CipherKey(std::string(name));
	}
	catch (Poco::Exception e) {
		//DEBUGPOINT("KEY FORMATION FAILED [%s]\n", e.message().c_str());
		luaL_error(L, "KEY FORMATION FAILED [%s]\n", e.message().c_str());
	}
	catch (std::exception e) {
		//DEBUGPOINT("KEY FORMATION FAILED [%s]\n", e.what());
		luaL_error(L, e.what());
	}

	void * ptr = lua_newuserdata(L, sizeof(CipherKey *));
	*((CipherKey **)ptr) = key;
	luaL_setmetatable(L, _cipher_key_name);

	return 1;
}

static int generate_rsa_key_pair(lua_State *L)
{
	return 0;
}

static int encrypt_symm_key(lua_State *L)
{
	return 0;
}

static int decrypt_symm_key(lua_State *L)
{
	return 0;
}

static int encrypt_text(lua_State *L)
{
	const char * text = luaL_checkstring(L, 1);
	CipherKey * key = *((CipherKey **)luaL_checkudata(L, 2, _cipher_key_name));


	size_t textlen = strlen(text);
	size_t keylen = key->keySize();
	size_t ivlen = key->ivSize();
	size_t bufferlen = ivlen;
	while (bufferlen < textlen) bufferlen += ivlen;

	char ** buffer_ptr = (char **)lua_newuserdata(L, sizeof(char*));
	*(char**)buffer_ptr = (char*)malloc(bufferlen);
	luaL_setmetatable(L, _cipher_text_name);

	Poco::MemoryOutputStream   ostream(*buffer_ptr, bufferlen);
	std::istringstream source(text);

	std::string s;
	try {
		CipherFactory& factory = CipherFactory::defaultFactory();
		Cipher* pCipher = factory.createCipher(*key);
		pCipher->encrypt(source, ostream);
	}
	catch (Poco::Exception e) {
		luaL_error(L, "ENCRYPTION FAILED [%s]\n", e.message().c_str());
	}
	catch (std::exception e) {
		luaL_error(L, e.what());
	}

	lua_pushinteger(L, bufferlen);

	return 2;
}

static int decrypt_text(lua_State *L)
{
	char * cipher_text = *(char**)luaL_checkudata(L, 1, _cipher_text_name);
	size_t bufferlen = luaL_checkinteger(L, 2);
	CipherKey * key = *((CipherKey **)luaL_checkudata(L, 3, _cipher_key_name));

	Poco::MemoryInputStream source(cipher_text, bufferlen);

	char * plain_text = (char*)malloc(bufferlen + 1);
	memset(plain_text, 0, bufferlen+1);
	Poco::MemoryOutputStream   ostream(plain_text, bufferlen);

	try {
		CipherFactory& factory = CipherFactory::defaultFactory();
		Cipher* pCipher = factory.createCipher(*key);
		pCipher->decrypt(source, ostream);
	}
	catch (Poco::Exception e) {
		luaL_error(L, "DECRYPTION FAILED [%s]\n", e.message().c_str());
	}
	catch (std::exception e) {
		luaL_error(L, e.what());
	}

	lua_pushstring(L, plain_text);

	return 1;
}

extern "C" int luaopen_libevlcrypto(lua_State *L);
int luaopen_libevlcrypto(lua_State *L)
{
	static const luaL_Reg lua_crypto_methods[] = {
		 {"s_sha1_hash", generate_hash_from_string_sha1}
		,{"s_sha256_hash", generate_hash_from_string_sha256}
		,{"s_sha384_hash", generate_hash_from_string_sha384}
		,{"s_sha512_hash", generate_hash_from_string_sha512}
		,{"hmac_digest", hmac_fdigest}
		,{"generate_aes_key", generate_aes_key}
		,{"generate_rsa_key_pair", generate_rsa_key_pair}
		,{"encrypt_symm_key", encrypt_symm_key}
		,{"decrypt_symm_key", decrypt_symm_key}
		,{"encrypt_text", encrypt_text}
		,{"decrypt_text", decrypt_text}
		,{NULL, NULL}
	};

	{
		// Stack:
		luaL_newmetatable(L, _cipher_key_name); // Stack: meta
		luaL_newlib(L, _lib); // Stack: meta _lib
		lua_setfield(L, -2, "__index"); // Stack: meta
		lua_pushstring(L, "__gc"); // Stack: meta "__gc"
		lua_pushcfunction(L, cipher_key__gc); // Stack: meta "__gc" fptr
		lua_settable(L, -3); // Stack: meta
		lua_pushcfunction(L, cipher_key__tostring); // Stack: context meta fptr
		lua_setfield(L, -2, "__tostring"); // Stack: context meta
		lua_pop(L, 1);
		// Stack: 
	}
	{
		// Stack:
		luaL_newmetatable(L, _cipher_text_name); // Stack: meta
		luaL_newlib(L, _lib); // Stack: meta _lib
		lua_setfield(L, -2, "__index"); // Stack: meta
		lua_pushstring(L, "__gc"); // Stack: meta "__gc"
		lua_pushcfunction(L, cipher_text__gc); // Stack: meta "__gc" fptr
		lua_settable(L, -3); // Stack: meta
		lua_pushcfunction(L, cipher_text__tostring); // Stack: context meta fptr
		lua_setfield(L, -2, "__tostring"); // Stack: context meta
		lua_pop(L, 1);
		// Stack: 
	}

	OpenSSL_add_all_algorithms();

	luaL_newlib(L, lua_crypto_methods);
	return 1;    
}

