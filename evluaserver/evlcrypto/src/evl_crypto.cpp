#include <stdlib.h>
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
#include <openssl/evp.h>
#include <stddef.h>
#include <assert.h>
#include <arpa/inet.h>

extern "C" {
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include <string.h>
}

#include <sstream>

#include "Poco/MemoryStream.h"

#include "Poco/Crypto/DigestEngine.h"
#include "Poco/Crypto/CipherFactory.h"
#include "Poco/Crypto/Cipher.h"
#include "Poco/Crypto/CipherKey.h"
#include "Poco/Crypto/RSAKey.h"
#include "Poco/Crypto/EVPPKey.h"

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

#if defined __linux__
#ifdef ntohll
#undef ntohll
#endif
#ifdef htonll
#undef htonll
#endif
#include <endian.h>
#define ntohll be64toh
#define htonll htobe64
#endif


extern "C" {
unsigned char *base64_encode(const unsigned char *data, size_t input_length, size_t *output_length, int add_line_breaks);
unsigned char *base64_decode(const unsigned char *data, size_t input_length, size_t *output_length);
}

using namespace Poco::Crypto;


static int hmac_fdigest(lua_State *L)
{
    const char *t = luaL_checkstring(L, 1);
    size_t slen; const char *s;
    size_t klen; const char *k;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int written = 0;

    memset(digest, 0, EVP_MAX_MD_SIZE);

    s = luaL_checklstring(L, 2, &slen);
    k = luaL_checklstring(L, 3, &klen);


#if ((defined OPENSSL_VERSION_MAJOR) && (OPENSSL_VERSION_MAJOR >=3))
    /*
     * Reference for the below code is
     * man EVP_MAC_CTX_new, example in the end of the man page
     *
     * There seems to be another implementation possible in
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


    /*
    OpenSSL_add_all_digests();
    EVP_MD_CTX* mdctx = NULL;
    const EVP_MD* type = NULL;
    EVP_PKEY *pkey = NULL;

    OpenSSL_add_all_digests();

    mdctx = EVP_MD_CTX_new();
    type = EVP_get_digestbyname(t);
    if (type == NULL) {
        luaL_argerror(L, 1, "invalid digest type");
        return 0;
    }

    pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, (unsigned char *)k, klen);

    EVP_DigestSignInit(mdctx, NULL, type, NULL, pkey);

    EVP_DigestSignUpdate(mdctx, s, slen);

    EVP_DigestSignFinal(mdctx, (unsigned char *)digest, (size_t*)&written);
    DEBUGPOINT("written = [%d]\n", written);

    EVP_PKEY_free(pkey);
    EVP_MD_CTX_free(mdctx);
    */

#else
    const EVP_MD *type = EVP_get_digestbyname(t);
    if (type == NULL) {
        luaL_argerror(L, 1, "invalid digest type");
        return 0;
    }

    /*
    */
    //HMAC_CTX_init(&c);
    HMAC_CTX * c = HMAC_CTX_new();
    HMAC_CTX_reset(c);
    HMAC_Init_ex(c, k, klen, type, NULL);
    HMAC_Update(c, (unsigned char *)s, slen);
    HMAC_Final(c, digest, &written);
    //HMAC_CTX_cleanup(c);
    HMAC_CTX_free(c);
#endif

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
    //const char * salt = luaL_tolstring(L, 2, NULL);
    const char * salt = luaL_optlstring(L, 2, NULL, NULL);
    size_t len = strlen(inp_str) + ((salt)?strlen(salt):0);
    char * str = (char*)malloc(len+1);
    memset(str, 0, len+1);
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
    unsigned char * buffer;
    size_t len;
};

const static char *_cipher_text_name = "cipher_text";
static int cipher_text__gc(lua_State *L)
{
    struct cipher_text_s * ptr = (cipher_text_s *)luaL_checkudata(L, 1, _cipher_text_name);
    if(ptr) free(ptr->buffer);
    return 0;
}

static int cipher_text__tostring(lua_State *L)
{
    struct cipher_text_s * ptr = (cipher_text_s *)luaL_checkudata(L, 1, _cipher_text_name);
    lua_pushfstring(L, "%s:%p", _cipher_text_name, ptr->buffer);
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

static int generate_symmetric_key(lua_State *L)
{
    const char * name = luaL_checkstring(L, 1);
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

    size_t keylen = key->keySize();
    size_t ivlen = key->ivSize();
    size_t block_size = key->blockSize();

    //DEBUGPOINT("Here block_size = [%zu]\n", block_size);
    //DEBUGPOINT("Here ivlen = [%zu]\n", ivlen);
    //DEBUGPOINT("Here keylen = [%zu]\n", keylen);

    void * ptr = lua_newuserdata(L, sizeof(CipherKey *));
    *((CipherKey **)ptr) = key;
    luaL_setmetatable(L, _cipher_key_name);

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

const static char *_rsa_key_name = "rsa_key";
static int rsa_key__gc(lua_State *L)
{
    RSAKey * ptr = *(RSAKey **)luaL_checkudata(L, 1, _rsa_key_name);
    delete ptr;
    return 0;
}

static int rsa_key__tostring(lua_State *L)
{
    RSAKey * ptr = *(RSAKey **)luaL_checkudata(L, 1, _rsa_key_name);
    lua_pushfstring(L, "%s:%p", _rsa_key_name, ptr);
    return 1;
}

static int get_rsa_public_key(lua_State *L)
{
    RSAKey * rsa_key = *(RSAKey **)luaL_checkudata(L, 1, _rsa_key_name);

    char * buffer_ptr = (char*)malloc(8192);
    memset(buffer_ptr, 0, 8192);
    Poco::MemoryOutputStream   ostream(buffer_ptr, 8192);

    try {
        rsa_key->impl()->save(&ostream);
    }
    catch (Poco::Exception e) {
        free(buffer_ptr);
        luaL_error(L, "SAVING RSA PUBLIC KEY FAILED [%s]\n", e.message().c_str());
    }
    catch (std::exception e) {
        free(buffer_ptr);
        luaL_error(L, e.what());
    }

    lua_pushstring(L, buffer_ptr);
    free(buffer_ptr);

    return 1;
}

static int load_rsa_public_key(lua_State *L)
{
    const char * rsa_pub_key_buffer = luaL_checkstring(L, 1);
    std::istringstream source(rsa_pub_key_buffer);

    RSAKey * rsa_key = NULL;
    try {
        rsa_key = new RSAKey(&source);
    }
    catch (Poco::Exception e) {
        luaL_error(L, "LOASDING RSA PUBLIC KEY FAILED [%s]\n", e.message().c_str());
    }
    catch (std::exception e) {
        luaL_error(L, e.what());
    }

    void * ptr = lua_newuserdata(L, sizeof(RSAKey *));
    *((RSAKey **)ptr) = rsa_key;
    luaL_setmetatable(L, _rsa_key_name);

    return 1;
}

static int get_rsa_private_key(lua_State *L)
{
    RSAKey * rsa_key = *(RSAKey **)luaL_checkudata(L, 1, _rsa_key_name);

    char * buffer_ptr = (char*)malloc(8192);
    memset(buffer_ptr, 0, 8192);
    Poco::MemoryOutputStream   ostream(buffer_ptr, 8192);

    try {
        rsa_key->impl()->save(NULL, &ostream);
    }
    catch (Poco::Exception e) {
        free(buffer_ptr);
        luaL_error(L, "SAVING RSA PRIVATE KEY FAILED [%s]\n", e.message().c_str());
    }
    catch (std::exception e) {
        free(buffer_ptr);
        luaL_error(L, e.what());
    }

    lua_pushstring(L, buffer_ptr);
    free(buffer_ptr);

    return 1;
}

static int load_rsa_private_key(lua_State *L)
{
    const char * rsa_prv_key_buffer = luaL_checkstring(L, 1);
    std::istringstream source(rsa_prv_key_buffer);

    RSAKey * rsa_key = NULL;
    try {
        rsa_key = new RSAKey(NULL, &source);
    }
    catch (Poco::Exception e) {
        luaL_error(L, "LOASDING RSA PRIVATE KEY FAILED [%s]\n", e.message().c_str());
    }
    catch (std::exception e) {
        luaL_error(L, e.what());
    }

    void * ptr = lua_newuserdata(L, sizeof(RSAKey *));
    *((RSAKey **)ptr) = rsa_key;
    luaL_setmetatable(L, _rsa_key_name);

    return 1;
}

static int generate_rsa_key_pair(lua_State *L)
{
    int key_length = luaL_checkinteger(L, 1);
    switch(key_length) {
        case 512:
        case 1024:
        case 2048:
        case 4096:
            break;
        default:
            luaL_error(L, "Invalid key length, must be one of (512, 1024, 2048 or 4096)");
            return 0;
    }
    RSAKey::KeyLength kl = (RSAKey::KeyLength)key_length;;
    RSAKey * rsa_key = NULL;
    try {
        rsa_key = new RSAKey(kl, RSAKey::EXP_LARGE);
    }
    catch (Poco::Exception e) {
        //DEBUGPOINT("RSA KEY FORMATION FAILED [%s]\n", e.message().c_str());
        luaL_error(L, "RSA KEY FORMATION FAILED [%s]\n", e.message().c_str());
    }
    catch (std::exception e) {
        //DEBUGPOINT("RSA KEY FORMATION FAILED [%s]\n", e.what());
        luaL_error(L, e.what());
    }

    void * ptr = lua_newuserdata(L, sizeof(RSAKey *));
    *((RSAKey **)ptr) = rsa_key;
    luaL_setmetatable(L, _rsa_key_name);

    return 1;
}

static CipherKey * deserialize_symmetric_key(lua_State *L, unsigned char * data)
{
    unsigned int name_len = 0;
    unsigned int key_len = 0;
    unsigned int iv_len = 0;
    std::string name;
    std::vector<unsigned char> symm_key;
    std::vector<unsigned char> iv;

    unsigned int be_name_len = 0;
    unsigned int be_key_len = 0;
    unsigned int be_iv_len = 0;

    unsigned char * ptr = data;

    {
        memcpy(&be_name_len, ptr, sizeof(unsigned int)); /* name len -> 4 bytes */
        name_len = ntohl(be_name_len);
        ptr += sizeof(unsigned int);
        name = std::string((const char*)ptr, name_len); /* name -> variable bytes */
        ptr += name_len;
        memcpy(&be_key_len, ptr, sizeof(unsigned int)); /* key_len len -> 4 bytes */
        key_len = ntohl(be_key_len);
        ptr += sizeof(unsigned int);
        for (int i = 0; i < key_len; i++) /* key -> vaiable bytes */ {
            symm_key.push_back(ptr[i]);
        }
        ptr += key_len;
        memcpy(&be_iv_len, ptr, sizeof(unsigned int)); /* iv_len len -> 4 bytes */
        iv_len = ntohl(be_iv_len);
        ptr += sizeof(unsigned int);
        for (int i = 0; i < iv_len; i++) /* iv -> vaiable bytes */ {
            iv.push_back(ptr[i]);
        }
        ptr += iv_len;
    }

    CipherKey * cipher_key = NULL;
    try {
        cipher_key = new CipherKey(name, symm_key, iv);
    }
    catch (Poco::Exception e) {
        //DEBUGPOINT("CIPHER FORMATION FAILED\n");
        luaL_error(L, "CIPHER FORMATION FAILED :%s\n", e.message().c_str());
    }
    catch (std::exception e) {
        //DEBUGPOINT("CIPHER FORMATION FAILED : %s\n", e.what());
        luaL_error(L, "CIPHER FORMATION FAILED\n");
    }
    catch (...) {
        //DEBUGPOINT("CIPHER FORMATION FAILED\n");
        luaL_error(L, "CIPHER FORMATION FAILED\n");
    }

    return cipher_key;
}

struct serialized_cipher_key_s {
    unsigned char * buffer;
    size_t buffer_size;
};

static void serialize_symmetric_key(lua_State *L, CipherKey * key, struct serialized_cipher_key_s * s_cipher_key_p)
{
    unsigned int name_len = strlen(key->name().c_str());
    unsigned int key_len = key->keySize();
    unsigned int iv_len = key->ivSize();
    std::vector<unsigned char> symm_key = key->getKey();
    std::vector<unsigned char> iv = key->getIV();

    unsigned int be_name_len = htonl(name_len);
    unsigned int be_key_len = htonl(key_len);
    unsigned int be_iv_len = htonl(iv_len);

    s_cipher_key_p->buffer_size = sizeof(unsigned int) + name_len +
                    sizeof(unsigned int) + key_len + sizeof(unsigned int) + iv_len;
    s_cipher_key_p->buffer = (unsigned char *)malloc(s_cipher_key_p->buffer_size);
    memset(s_cipher_key_p->buffer, 0, s_cipher_key_p->buffer_size);
    unsigned char * ptr = s_cipher_key_p->buffer;

    {
        memcpy(ptr, &be_name_len, sizeof(unsigned int)); /* name len -> 4 bytes */
        ptr += sizeof(unsigned int);
        memcpy(ptr, key->name().c_str(), name_len); /* name -> variable bytes */
        ptr += name_len;
        memcpy(ptr, &be_key_len, sizeof(unsigned int)); /* key_len len -> 4 bytes */
        ptr += sizeof(unsigned int);
        memcpy(ptr, &symm_key[0], key_len); /* key -> vaiable bytes */
        ptr += key_len;
        memcpy(ptr, &be_iv_len, sizeof(unsigned int)); /* iv_len len -> 4 bytes */
        ptr += sizeof(unsigned int);
        memcpy(ptr, &iv[0], iv_len); /* iv -> vaiable bytes */
        ptr += iv_len;
    }

    return ;
}

static int rsa_encrypt_symm_key(lua_State *L)
{
    CipherKey * key = *((CipherKey **)luaL_checkudata(L, 1, _cipher_key_name));
    RSAKey * rsa_key = *(RSAKey **)luaL_checkudata(L, 2, _rsa_key_name);

    Cipher* pRSACipher = NULL;
    try {
        CipherFactory& factory = CipherFactory::defaultFactory();
        pRSACipher = factory.createCipher(*rsa_key, RSA_PADDING_PKCS1_OAEP);
    }
    catch (Poco::Exception e) {
        luaL_error(L, "RSA CIPHER FORMATION FAILED [%s]\n", e.message().c_str());
    }
    catch (std::exception e) {
        luaL_error(L, e.what());
    }

    struct serialized_cipher_key_s s_cipher_key;
    serialize_symmetric_key(L, key, &s_cipher_key);

    if (rsa_key->impl()->size()  <= (s_cipher_key.buffer_size+42)) {
        luaL_error(L,
            "RSA modulus length [%d] is not enought to handle encryption of data of length [%d]\n",
            8*(rsa_key->impl()->size()), s_cipher_key.buffer_size);
    }

    unsigned char * crypto_buffer = (unsigned char *)malloc(rsa_key->impl()->size());
    memset(crypto_buffer, 0, rsa_key->impl()->size());
    Poco::MemoryInputStream istream((const char *)s_cipher_key.buffer, s_cipher_key.buffer_size);
    Poco::MemoryOutputStream ostream((char *)crypto_buffer, rsa_key->impl()->size());

    try {
        pRSACipher->encrypt(istream, ostream);
    }
    catch (Poco::Exception e) {
        //DEBUGPOINT("RSA ENCRYPTION FAILED [%s]\n", e.message().c_str());
        free(s_cipher_key.buffer);
        free(crypto_buffer);
        luaL_error(L, "RSA ENCRYPTION FAILED [%s]\n", e.message().c_str());
    }
    catch (std::exception e) {
        //DEBUGPOINT("RSA ENCRYPTION FAILED [%s]\n", e.what());
        free(s_cipher_key.buffer);
        free(crypto_buffer);
        luaL_error(L, "RSA ENCRYPTION FAILED [%s]", e.what());
    }
    free(s_cipher_key.buffer);

    cipher_text_s* cs_p = (cipher_text_s*)lua_newuserdata(L, sizeof(cipher_text_s));
    cs_p->buffer = crypto_buffer;
    cs_p->len = ostream.charsWritten();
    luaL_setmetatable(L, _cipher_text_name);


    lua_pushinteger(L, ostream.charsWritten());
    lua_pushlightuserdata(L, crypto_buffer);

    return 3;
}

static int rsa_decrypt_udata_enc_symm_key(lua_State *L)
{
    //cipher_text_s * cipher_text = (cipher_text_s*)luaL_checkudata(L, 1, _cipher_text_name);
    char * cipher_text = (char*)lua_touserdata(L, 1);
    if (cipher_text == NULL) {
        luaL_error(L, "Expect userdata as argument 1 got [%s]", lua_typename(L, lua_type(L, 1)));
    }
    size_t bufferlen = luaL_checkinteger(L, 2);

    RSAKey * rsa_key = *(RSAKey **)luaL_checkudata(L, 3, _rsa_key_name);

    Cipher* pRSACipher = NULL;
    try {
        CipherFactory& factory = CipherFactory::defaultFactory();
        pRSACipher = factory.createCipher(*rsa_key, RSA_PADDING_PKCS1_OAEP);
    }
    catch (Poco::Exception e) {
        luaL_error(L, "RSA CIPHER FORMATION FAILED [%s]\n", e.message().c_str());
    }
    catch (std::exception e) {
        luaL_error(L, e.what());
    }

    unsigned char * data = (unsigned char*)malloc(rsa_key->impl()->size());
    memset(data, 0, rsa_key->impl()->size());
    Poco::MemoryInputStream istream((char *)cipher_text, rsa_key->impl()->size());
    Poco::MemoryOutputStream ostream((char *)data, rsa_key->impl()->size());

    try {
        pRSACipher->decrypt(istream, ostream);
    }
    catch (Poco::Exception e) {
        free(data);
        luaL_error(L, "RSA DECRYPTION FAILED [%s]\n", e.message().c_str());
    }
    catch (std::exception e) {
        free(data);
        luaL_error(L, e.what());
    }

    CipherKey* cipher_key = deserialize_symmetric_key(L, data);
    free(data);

    void * ptr = lua_newuserdata(L, sizeof(CipherKey *));
    *((CipherKey **)ptr) = cipher_key;
    luaL_setmetatable(L, _cipher_key_name);

    return 1;
}

static int rsa_decrypt_enc_symm_key(lua_State *L)
{
    cipher_text_s * cipher_text = (cipher_text_s*)luaL_checkudata(L, 1, _cipher_text_name);

    RSAKey * rsa_key = *(RSAKey **)luaL_checkudata(L, 2, _rsa_key_name);

    Cipher* pRSACipher = NULL;
    try {
        CipherFactory& factory = CipherFactory::defaultFactory();
        pRSACipher = factory.createCipher(*rsa_key, RSA_PADDING_PKCS1_OAEP);
    }
    catch (Poco::Exception e) {
        luaL_error(L, "RSA CIPHER FORMATION FAILED [%s]\n", e.message().c_str());
    }
    catch (std::exception e) {
        luaL_error(L, e.what());
    }

    unsigned char * data = (unsigned char*)malloc(rsa_key->impl()->size());
    memset(data, 0, rsa_key->impl()->size());
    Poco::MemoryInputStream istream((char *)cipher_text->buffer, rsa_key->impl()->size());
    Poco::MemoryOutputStream ostream((char *)data, rsa_key->impl()->size());

    try {
        pRSACipher->decrypt(istream, ostream);
    }
    catch (Poco::Exception e) {
        free(data);
        luaL_error(L, "RSA ENCRYPTION FAILED [%s]\n", e.message().c_str());
    }
    catch (std::exception e) {
        free(data);
        luaL_error(L, e.what());
    }

    CipherKey* cipher_key = deserialize_symmetric_key(L, data);
    free(data);

    void * ptr = lua_newuserdata(L, sizeof(CipherKey *));
    *((CipherKey **)ptr) = cipher_key;
    luaL_setmetatable(L, _cipher_key_name);


    return 1;
}

static int rsa_decrypt_b64_enc_symm_key(lua_State *L)
{
    char * b64_cipher_text = (char*)luaL_checkstring(L, 1);

    RSAKey * rsa_key = *(RSAKey **)luaL_checkudata(L, 2, _rsa_key_name);

    Cipher* pRSACipher = NULL;
    try {
        CipherFactory& factory = CipherFactory::defaultFactory();
        pRSACipher = factory.createCipher(*rsa_key, RSA_PADDING_PKCS1_OAEP);
    }
    catch (Poco::Exception e) {
        luaL_error(L, "RSA CIPHER FORMATION FAILED [%s]\n", e.message().c_str());
    }
    catch (std::exception e) {
        luaL_error(L, e.what());
    }

    unsigned char * data = (unsigned char*)malloc(rsa_key->impl()->size());
    memset(data, 0, rsa_key->impl()->size());
    Poco::MemoryInputStream istream((char *)b64_cipher_text, strlen(b64_cipher_text));
    Poco::MemoryOutputStream ostream((char *)data, rsa_key->impl()->size());

    try {
        pRSACipher->decrypt(istream, ostream, Cipher::ENC_BASE64);
    }
    catch (Poco::Exception e) {
        free(data);
        DEBUGPOINT("RSA DECRYPTION FAILED\n");
        luaL_error(L, "RSA DECRYPTION FAILED [%s]\n", e.message().c_str());
    }
    catch (std::exception e) {
        free(data);
        DEBUGPOINT("RSA DECRYPTION FAILED\n");
        luaL_error(L, e.what());
    }
    catch (...) {
        free(data);
        DEBUGPOINT("RSA ENCRYPTION FAILED\n");
        luaL_error(L, "RSA ENCRYPTION FAILED");
    }

    CipherKey* cipher_key = deserialize_symmetric_key(L, data);
    free(data);

    void * ptr = lua_newuserdata(L, sizeof(CipherKey *));
    *((CipherKey **)ptr) = cipher_key;
    luaL_setmetatable(L, _cipher_key_name);

    return 1;
}

static int encrypt_text(lua_State *L)
{
    const char * text = luaL_checkstring(L, 1);
    CipherKey * key = *((CipherKey **)luaL_checkudata(L, 2, _cipher_key_name));


    size_t keylen = key->keySize();
    size_t ivlen = key->ivSize();
    size_t block_size = key->blockSize();

    //DEBUGPOINT("Here block_size = [%zu]\n", block_size);

    size_t bufferlen = strlen(text);

    /* Additional block for padding if required */
    bufferlen += (bufferlen % block_size) ? (block_size - (bufferlen % block_size)) : block_size;

    //DEBUGPOINT("Here bufferlen = [%zu]\n", bufferlen);
    //DEBUGPOINT("Here ivlen = [%zu]\n", ivlen);
    //DEBUGPOINT("Here keylen = [%zu]\n", keylen);

    cipher_text_s* cs_p = (cipher_text_s*)lua_newuserdata(L, sizeof(cipher_text_s));
    cs_p->buffer = (unsigned char*)malloc(bufferlen);
    memset(cs_p->buffer, 0, bufferlen);
    cs_p->len = bufferlen;
    luaL_setmetatable(L, _cipher_text_name);

    Poco::MemoryOutputStream   ostream((char*)(cs_p->buffer), bufferlen);
    std::istringstream source(text);

    std::string s;
    try {
        CipherFactory& factory = CipherFactory::defaultFactory();
        Cipher* pCipher = factory.createCipher(*key);
        pCipher->encrypt(source, ostream);
    }
    catch (Poco::Exception e) {
        free(cs_p->buffer);
        luaL_error(L, "ENCRYPTION FAILED [%s]\n", e.message().c_str());
    }
    catch (std::exception e) {
        free(cs_p->buffer);
        luaL_error(L, e.what());
    }

    lua_pushinteger(L, bufferlen);
    lua_pushlightuserdata(L, (cs_p->buffer));

    return 3;
}

static int decrypt_cipher_text(lua_State *L)
{
    cipher_text_s * cipher_text = (cipher_text_s*)luaL_checkudata(L, 1, _cipher_text_name);
    CipherKey * key = *((CipherKey **)luaL_checkudata(L, 2, _cipher_key_name));

    size_t bufferlen = cipher_text->len;
    //DEBUGPOINT("Here bufferlen = [%zu]\n", bufferlen);

    Poco::MemoryInputStream source((const char*)(cipher_text->buffer), bufferlen);

    char * plain_text = (char*)malloc(bufferlen + 1);
    memset(plain_text, 0, bufferlen+1);
    Poco::MemoryOutputStream   ostream(plain_text, bufferlen);

    try {
        CipherFactory& factory = CipherFactory::defaultFactory();
        Cipher* pCipher = factory.createCipher(*key);
        pCipher->decrypt(source, ostream);
    }
    catch (Poco::Exception e) {
        free(plain_text);
        luaL_error(L, "DECRYPTION FAILED [%s]\n", e.message().c_str());
    }
    catch (std::exception e) {
        free(plain_text);
        luaL_error(L, e.what());
    }

    plain_text[ostream.charsWritten()] = '\0';

    lua_pushstring(L, plain_text);
    free(plain_text);

    return 1;
}

static int decrypt_b64_cipher_text(lua_State *L)
{
    char * b64_cipher_text = (char*)luaL_checkstring(L, 1);

    size_t bufferlen = luaL_checkinteger(L, 2);
    CipherKey * key = *((CipherKey **)luaL_checkudata(L, 3, _cipher_key_name));

    Poco::MemoryInputStream source((const char*)(b64_cipher_text), strlen(b64_cipher_text));

    char * plain_text = (char*)malloc(bufferlen + 1);
    memset(plain_text, 0, bufferlen+1);
    Poco::MemoryOutputStream   ostream(plain_text, bufferlen);

    try {
        CipherFactory& factory = CipherFactory::defaultFactory();
        Cipher* pCipher = factory.createCipher(*key);
        pCipher->decrypt(source, ostream, Cipher::ENC_BASE64);
    }
    catch (Poco::Exception e) {
        free(plain_text);
        luaL_error(L, "DECRYPTION FAILED [%s]\n", e.message().c_str());
    }
    catch (std::exception e) {
        free(plain_text);
        luaL_error(L, e.what());
    }

    plain_text[ostream.charsWritten()] = '\0';

    lua_pushstring(L, plain_text);
    free(plain_text);

    return 1;
}

static int decrypt_udata_cipher_text(lua_State *L)
{
    char * cipher_text = (char*)lua_touserdata(L, 1);
    if (cipher_text == NULL) {
        luaL_error(L, "Expect userdata as argument 1 got [%s]", lua_typename(L, lua_type(L, 1)));
    }

    size_t bufferlen = luaL_checkinteger(L, 2);
    CipherKey * key = *((CipherKey **)luaL_checkudata(L, 3, _cipher_key_name));

    Poco::MemoryInputStream source((const char*)(cipher_text), bufferlen);

    char * plain_text = (char*)malloc(bufferlen + 1);
    memset(plain_text, 0, bufferlen+1);
    Poco::MemoryOutputStream   ostream(plain_text, bufferlen);

    try {
        CipherFactory& factory = CipherFactory::defaultFactory();
        Cipher* pCipher = factory.createCipher(*key);
        pCipher->decrypt(source, ostream);
    }
    catch (Poco::Exception e) {
        free(plain_text);
        luaL_error(L, "DECRYPTION FAILED [%s]\n", e.message().c_str());
    }
    catch (std::exception e) {
        free(plain_text);
        luaL_error(L, e.what());
    }

    plain_text[ostream.charsWritten()] = '\0';

    lua_pushstring(L, plain_text);
    free(plain_text);

    return 1;
}

static EVPPKey * form_evp_key_from_rsa_key(const char * rsa_prv_key_buffer, const char * rsa_pub_key_buffer)
{
    if (rsa_prv_key_buffer != NULL) {
        std::istringstream prv_source(rsa_prv_key_buffer);
        EVPPKey * kp = new EVPPKey(NULL, &prv_source);
        return kp;
    }
    else {
        std::istringstream pub_source(rsa_pub_key_buffer);
        EVPPKey * kp = new EVPPKey(&pub_source, NULL);
        return kp;
    }

}

static int sign_message(lua_State *L)
{
    const char * text = luaL_checkstring(L, 1);
    size_t bufferlen = strlen(text);
    const char * rsa_prv_key_buffer = luaL_checkstring(L, 2);
    const char * digest_name = luaL_checkstring(L, 3);
    size_t sig_len = 0;

    EVPPKey* evpPkey = form_evp_key_from_rsa_key(rsa_prv_key_buffer, NULL);
    EVP_PKEY* pkey = static_cast<EVP_PKEY*>(*evpPkey);

    EVP_MD_CTX* mdctx = NULL;
    mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        DEBUGPOINT("Error creating EVP_MD_CTX\n");
        delete evpPkey;
        return 0;
    }

    if (EVP_DigestSignInit(mdctx, NULL, EVP_get_digestbyname(digest_name), NULL, pkey) <= 0) {
        DEBUGPOINT("Error initializing DigestSign\n");
        EVP_MD_CTX_free(mdctx);
        delete evpPkey;
        return 0;
    }

    if (EVP_DigestSignUpdate(mdctx, text, bufferlen) <= 0) {
        DEBUGPOINT("Error updating DigestSign\n");
        EVP_MD_CTX_free(mdctx);
        delete evpPkey;
        return 0;
    }

    if (EVP_DigestSignFinal(mdctx, NULL, &sig_len) <= 0) {
        DEBUGPOINT("Error obtaining signature length\n");
        EVP_MD_CTX_free(mdctx);
        delete evpPkey;
        return 0;
    }

    unsigned char* sig = (unsigned char*)malloc(sig_len+1);
    if (sig == NULL) {
        DEBUGPOINT("Memory allocation failed\n");
        EVP_MD_CTX_free(mdctx);
        delete evpPkey;
        return 0;
    }
    memset(sig, 0, sig_len+1);

    if (EVP_DigestSignFinal(mdctx, sig, &sig_len) <= 0) {
        DEBUGPOINT("Error during DigestSignFinal\n");
        EVP_MD_CTX_free(mdctx);
        delete evpPkey;
        free(sig);
        return 0;
    }

    EVP_MD_CTX_free(mdctx);
    delete evpPkey;

    lua_pushlstring(L, (char*)sig, (int)sig_len);
    free(sig);
    /*
    size_t b64_len;
    unsigned char * b64_sig = base64_encode(sig, sig_len, &b64_len, 1);
    free(sig);

    lua_pushstring(L, (char*)b64_sig);
    free(b64_sig);
    */

    return 1;
}

static int verify_signature(lua_State *L)
{
    const char * text = luaL_checkstring(L, 1);
    size_t bufferlen = strlen(text);
    const char * rsa_pub_key_buffer = luaL_checkstring(L, 2);
    const char * digest_name = luaL_checkstring(L, 3);
    size_t sig_len = 0;
    const unsigned char * sig = (const unsigned char *)luaL_checklstring(L, 4, &sig_len);
    /*
    size_t sig_len = (size_t)strlen((char*)sig);

    sig = base64_decode(sig, sig_len, &sig_len);
    */

    EVPPKey* evpPkey = form_evp_key_from_rsa_key(NULL, rsa_pub_key_buffer);
    EVP_PKEY* pkey = static_cast<EVP_PKEY*>(*evpPkey);


    EVP_MD_CTX* md_ctx = NULL;
    md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        DEBUGPOINT("Error creating EVP_MD_CTX\n");
        delete evpPkey;
        return 0;
    }

    // Initialize the DigestVerify operation
    if (EVP_DigestVerifyInit(md_ctx, NULL, EVP_get_digestbyname(digest_name), NULL, pkey) <= 0) {
        DEBUGPOINT("Error initializing DigestVerify\n");
        EVP_MD_CTX_free(md_ctx);
        delete evpPkey;
        return 0;
    }

    // Update the context with the message data
    if (EVP_DigestVerifyUpdate(md_ctx, text, bufferlen) <= 0) {
        DEBUGPOINT("Error updating DigestVerify\n");
        EVP_MD_CTX_free(md_ctx);
        delete evpPkey;
        return 0;
    }

    // Verify the signature
    int result = EVP_DigestVerifyFinal(md_ctx, sig, sig_len);
    EVP_MD_CTX_free(md_ctx);
    //free((void*)sig);
    delete evpPkey;

    lua_pushboolean(L, (result == 1));

    return 1;
}

static int verify_signature_prv_key(lua_State *L)
{
    const char * text = luaL_checkstring(L, 1);
    size_t bufferlen = strlen(text);
    const char * rsa_prv_key_buffer = luaL_checkstring(L, 2);
    const char * digest_name = luaL_checkstring(L, 3);
    size_t sig_len = 0;
    const unsigned char * sig = (const unsigned char *)luaL_checklstring(L, 4, &sig_len);
    /*
    const unsigned char * sig = (const unsigned char *)luaL_checkstring(L, 4);
    size_t sig_len = (size_t)strlen((char*)sig);

    sig = base64_decode(sig, sig_len, &sig_len);
    */

    EVPPKey* evpPkey = form_evp_key_from_rsa_key(rsa_prv_key_buffer, NULL);
    EVP_PKEY* pkey = static_cast<EVP_PKEY*>(*evpPkey);


    EVP_MD_CTX* md_ctx = NULL;
    md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        DEBUGPOINT("Error creating EVP_MD_CTX\n");
        delete evpPkey;
        return 0;
    }

    // Initialize the DigestVerify operation
    if (EVP_DigestVerifyInit(md_ctx, NULL, EVP_get_digestbyname(digest_name), NULL, pkey) <= 0) {
        DEBUGPOINT("Error initializing DigestVerify\n");
        EVP_MD_CTX_free(md_ctx);
        delete evpPkey;
        return 0;
    }

    // Update the context with the message data
    if (EVP_DigestVerifyUpdate(md_ctx, text, bufferlen) <= 0) {
        DEBUGPOINT("Error updating DigestVerify\n");
        EVP_MD_CTX_free(md_ctx);
        delete evpPkey;
        return 0;
    }

    // Verify the signature
    int result = EVP_DigestVerifyFinal(md_ctx, sig, sig_len);
    EVP_MD_CTX_free(md_ctx);
    //free((void*)sig);
    delete evpPkey;

    lua_pushboolean(L, (result == 1));

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

        ,{"generate_symmetric_key", generate_symmetric_key}
        ,{"generate_aes_key", generate_aes_key}
        ,{"generate_rsa_key_pair", generate_rsa_key_pair}

        ,{"get_rsa_public_key", get_rsa_public_key}
        ,{"get_rsa_private_key", get_rsa_private_key}

        ,{"load_rsa_public_key", load_rsa_public_key}
        ,{"load_rsa_private_key", load_rsa_private_key}


        ,{"rsa_encrypt_symm_key", rsa_encrypt_symm_key}

        ,{"rsa_decrypt_enc_symm_key", rsa_decrypt_enc_symm_key}
        ,{"rsa_decrypt_udata_enc_symm_key", rsa_decrypt_udata_enc_symm_key}
        ,{"rsa_decrypt_b64_enc_symm_key", rsa_decrypt_b64_enc_symm_key}


        ,{"encrypt_text", encrypt_text}

        ,{"decrypt_cipher_text", decrypt_cipher_text}
        ,{"decrypt_udata_cipher_text", decrypt_udata_cipher_text}
        ,{"decrypt_b64_cipher_text", decrypt_b64_cipher_text}

        ,{"sign_message", sign_message}
        ,{"verify_signature", verify_signature}
        ,{"verify_signature_prv_key", verify_signature_prv_key}

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
    {
        // Stack:
        luaL_newmetatable(L, _rsa_key_name); // Stack: meta
        luaL_newlib(L, _lib); // Stack: meta _lib
        lua_setfield(L, -2, "__index"); // Stack: meta
        lua_pushstring(L, "__gc"); // Stack: meta "__gc"
        lua_pushcfunction(L, rsa_key__gc); // Stack: meta "__gc" fptr
        lua_settable(L, -3); // Stack: meta
        lua_pushcfunction(L, rsa_key__tostring); // Stack: context meta fptr
        lua_setfield(L, -2, "__tostring"); // Stack: context meta
        lua_pop(L, 1);
        // Stack:
    }

    OpenSSL_add_all_algorithms();

    luaL_newlib(L, lua_crypto_methods);
    return 1;
}

