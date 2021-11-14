#include "Poco/Crypto/DigestEngine.h"
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


static int hmac_fdigest(lua_State *L)
{
    const char *t = luaL_checkstring(L, 1);
    const EVP_MD *type = EVP_get_digestbyname(t);
    size_t slen; const char *s;
    size_t klen; const char *k;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int written = 0;

    if (type == NULL) {
        luaL_argerror(L, 1, "invalid digest type");
        return 0;
    }

    s = luaL_checklstring(L, 2, &slen);
    k = luaL_checklstring(L, 3, &klen);


    //HMAC_CTX_init(&c);
    HMAC_CTX * c = HMAC_CTX_new();
	HMAC_CTX_reset(c);
    HMAC_Init_ex(c, k, klen, type, NULL);
    HMAC_Update(c, (unsigned char *)s, slen);
    HMAC_Final(c, digest, &written);
    //HMAC_CTX_cleanup(c);
	HMAC_CTX_free(c);

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

	Poco::Crypto::DigestEngine d(algo);
	d.update((const void *)str, len);

	std::string digest = d.digestToHex(d.digest());


	lua_pushstring(L, digest.c_str());

	free(str);
	return 1;
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

extern "C" int luaopen_libevlcrypto(lua_State *L);
int luaopen_libevlcrypto(lua_State *L)
{
	static const luaL_Reg lua_crypto_methods[] = {
		{"s_sha265_hash", generate_hash_from_string_sha256}
		,{"s_sha384_hash", generate_hash_from_string_sha384}
		,{"s_sha512_hash", generate_hash_from_string_sha512}
		,{"hmac_digest", hmac_fdigest}
		,{NULL, NULL}
	};

	luaL_newlib(L, lua_crypto_methods);


	return 1;    
}

