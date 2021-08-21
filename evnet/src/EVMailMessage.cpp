extern "C" {
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
}

#include "Poco/Net/MailMessage.h"
#include "Poco/Net/MailRecipient.h"
#include "Poco/Net/MailStream.h"
#include "Poco/Net/StringPartSource.h"
#include "Poco/evnet/EVStream.h"

using Poco::Net::MailMessage;
using Poco::Net::MailRecipient;
using Poco::Net::StringPartSource;

#define MAIL_MESSAGE "MAIL_MESSAGE"
#define CHUNKED_MEMORY_STREAM "CMS"

static int cms_gc(lua_State *L)
{
	void * ptr = lua_touserdata(L, 1);
	chunked_memory_stream * cms = *(chunked_memory_stream **)ptr;
	delete cms;
	return 0;
}

static int cms_tostring(lua_State *L)
{
	void * ptr = lua_touserdata(L, 1);
	chunked_memory_stream * cms = *(chunked_memory_stream**)ptr;
    lua_pushfstring(L, "%s:%p", CHUNKED_MEMORY_STREAM, cms);
	return 1;
}

static int mm_gc(lua_State *L)
{
	void * ptr = lua_touserdata(L, 1);
	MailMessage * mm = *(MailMessage**)ptr;
	delete mm;
	return 0;
}

static int mm_tostring(lua_State *L)
{
	void * ptr = lua_touserdata(L, 1);
	MailMessage * mm = *(MailMessage**)ptr;
    lua_pushfstring(L, "%s:%p", MAIL_MESSAGE, mm);
	return 1;
}

static int new_mail_message(lua_State *L)
{
	MailMessage * mm = new MailMessage();

	void * ptr = lua_newuserdata(L, sizeof(MailMessage*));
	*(MailMessage**)ptr = mm;

	luaL_newmetatable(L, MAIL_MESSAGE);

	lua_pushstring(L, "__gc");
	lua_pushcfunction(L, mm_gc);
	lua_settable(L, -3);

	lua_pushstring(L, "__tostring");
	lua_pushcfunction(L, mm_tostring);
	lua_settable(L, -3);

	lua_setmetatable(L, -2);

	return 1;
}

static int get_sender(lua_State *L)
{
	MailMessage * mm = *(MailMessage **)lua_touserdata(L, 1);
	if (mm == NULL) {
		return luaL_error(L, "get_sender: Invalid first argument");
	}
	const char * cp_sender = mm->getSender().c_str();
	if (cp_sender == NULL) {
		return luaL_error(L, "get_sender: Sender not set in the mail message");
	}
	if (strcmp(cp_sender, ""))
		lua_pushstring(L, cp_sender);
	else
		lua_pushnil(L);

	return 1;
}

static int set_sender(lua_State *L)
{
	MailMessage * mm = *(MailMessage **)lua_touserdata(L, 1);
	if (mm == NULL) {
		return luaL_error(L, "set_sender: Invalid first argument");
	}
	const char * cp_sender = luaL_checkstring(L, 2);
	mm->setSender(std::string(cp_sender));
	return 0;
}

static int get_recipients(lua_State *L)
{
	MailMessage * mm = *(MailMessage **)lua_touserdata(L, 1);
	if (mm == NULL) {
		return luaL_error(L, "get_recipients: Invalid first argument");
	}
	MailMessage::Recipients::const_iterator it;
	lua_newtable(L);
	int i = 0;
	for (it = mm->recipients().begin(); it != mm->recipients().end(); ++it) {
		i++;

		lua_newtable(L);

		const char * cp = it->getRealName().c_str();
		if (strcmp(cp, "")) {
			lua_pushstring(L, it->getRealName().c_str());
			lua_setfield(L, -2, "real_name");
		}

		lua_pushinteger(L, (int)it->getType());
		lua_setfield(L, -2, "recipient_type");

		lua_pushstring(L, it->getAddress().c_str());
		lua_setfield(L, -2, "address");

		lua_seti(L, -2, i);

	}

	return 1;
}

static int add_recipient(lua_State *L)
{
	MailMessage * mm = *(MailMessage **)lua_touserdata(L, 1);
	if (mm == NULL) {
		return luaL_error(L, "add_recipient: Invalid first argument");
	}
	const char * cp_recipient = luaL_checkstring(L, 2);
	int cp_recipient_type = luaL_checkinteger(L, 3);
	switch (cp_recipient_type) {
		case MailRecipient::PRIMARY_RECIPIENT:
		case MailRecipient::CC_RECIPIENT:
		case MailRecipient::BCC_RECIPIENT:
			break;
		default:
			return luaL_error(L, "add_recipient: Invalid third argument");
	}
	mm->addRecipient(MailRecipient((MailRecipient::RecipientType)cp_recipient_type, std::string(cp_recipient)));
	return 0;
}

static int set_subject(lua_State *L)
{
	MailMessage * mm = *(MailMessage **)lua_touserdata(L, 1);
	if (mm == NULL) {
		return luaL_error(L, "set_subject: Invalid first argument");
	}
	const char * cp_subject = luaL_checkstring(L, 2);
	mm->setSubject(std::string(cp_subject));
	return 0;
}

static int add_content(lua_State *L)
{
	MailMessage * mm = *(MailMessage **)lua_touserdata(L, 1);
	if (mm == NULL) {
		return luaL_error(L, "add_content: Invalid first argument");
	}
	const char * cp_content = luaL_checkstring(L, 2);
	mm->addContent(new StringPartSource(cp_content));
	return 0;
}

static int add_attachment(lua_State *L)
{
	MailMessage * mm = *(MailMessage **)lua_touserdata(L, 1);
	if (mm == NULL) {
		return luaL_error(L, "add_attachment: Invalid first argument");
	}
	const unsigned char * cp_attachment = (const unsigned char *)lua_touserdata(L, 2);
	if (cp_attachment == NULL) {
		return luaL_error(L, "add_attachment: Invalid second argument");
	}
	size_t size = (size_t)luaL_checkinteger(L, 3);
	if (size == 0) {
		return luaL_error(L, "add_attachment: Invalid third argument");
	}
	const char * cp_attachment_name = luaL_checkstring(L, 4);
	std::string attachment(reinterpret_cast<const char*>(cp_attachment), size);
	const char * cp_content_type = luaL_checkstring(L, 5);
	mm->addAttachment(cp_attachment_name, new StringPartSource(attachment, cp_content_type));
	return 0;
}

static int serialize_message(lua_State *L)
{
	MailMessage * mm = *(MailMessage **)lua_touserdata(L, 1);
	if (mm == NULL) {
		return luaL_error(L, "serialize_message: Invalid first argument");
	}
	chunked_memory_stream * cms = new chunked_memory_stream();
	Poco::evnet::EVOutputStream m_o_s(cms);
	Poco::Net::MailOutputStream mail_stream(m_o_s);
	mm->write(mail_stream);
	mail_stream.close();
	m_o_s.flush();

	//lua_pushlightuserdata(L, cms);

	void * ptr = lua_newuserdata(L, sizeof(chunked_memory_stream*));
	*(chunked_memory_stream**)ptr = cms;

	int top = lua_gettop(L);

	luaL_newmetatable(L, CHUNKED_MEMORY_STREAM);

	lua_pushstring(L, "__gc");
	lua_pushcfunction(L, cms_gc);
	lua_settable(L, -3);

	lua_pushstring(L, "__tostring");
	lua_pushcfunction(L, cms_tostring);
	lua_settable(L, -3);

	lua_setmetatable(L, -2);

	return 1;
}

int get_mail_message_funcs(lua_State *L)
{
	static const luaL_Reg mail_message_funcs[] = {
		 {"new", new_mail_message}
		,{"get_sender", get_sender}
		,{"set_sender", set_sender}
		,{"add_recipient", add_recipient}
		,{"get_recipients", get_recipients}
		,{"set_subject", set_subject}
		,{"add_content", add_content}
		,{"add_attachment", add_attachment}
		,{"serialize_message", serialize_message}
		,{NULL, NULL}
	};

	lua_newtable(L);
	luaL_setfuncs(L, mail_message_funcs, 0);

	return 1;
}


