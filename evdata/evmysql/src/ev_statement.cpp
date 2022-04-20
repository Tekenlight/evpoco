#include "Poco/evdata/evmysql/ev_mysql.h"
#include "Poco/evnet/evnet_lua.h"

extern "C"
{
	int completion_common_routine(lua_State *L, int status, lua_KContext ctx);
	gen_lua_user_data_t *get_generic_lua_userdata(const char *name, void *data, size_t size);
}

static lua_push_type_t mysql_to_lua_push(unsigned int mysql_type)
{
	lua_push_type_t lua_type;

	switch (mysql_type)
	{
	case MYSQL_TYPE_NULL:
		lua_type = LUA_PUSH_NIL;
		break;

	case MYSQL_TYPE_TINY:
	case MYSQL_TYPE_YEAR:
	case MYSQL_TYPE_SHORT:
	case MYSQL_TYPE_INT24:
	case MYSQL_TYPE_LONG:
		lua_type = LUA_PUSH_INTEGER;
		break;

	case MYSQL_TYPE_FLOAT:
	case MYSQL_TYPE_DOUBLE:
	case MYSQL_TYPE_LONGLONG:
		lua_type = LUA_PUSH_NUMBER;
		break;

	default:
		lua_type = LUA_PUSH_STRING;
	}

	return lua_type;
}

static size_t mysql_buffer_size(MYSQL_FIELD *field)
{
	unsigned int mysql_type = field->type;
	size_t size = 0;

	switch (mysql_type)
	{
	case MYSQL_TYPE_TINY:
		size = 1;
		break;
	case MYSQL_TYPE_YEAR:
	case MYSQL_TYPE_SHORT:
		size = 2;
		break;
	case MYSQL_TYPE_INT24:
		size = 4;
		break;
	case MYSQL_TYPE_LONG:
		size = 4;
		break;
	case MYSQL_TYPE_LONGLONG:
		size = 8;
		break;
	case MYSQL_TYPE_FLOAT:
		size = 4;
		break;
	case MYSQL_TYPE_DOUBLE:
		size = 8;
		break;
	case MYSQL_TYPE_TIME:
	case MYSQL_TYPE_DATE:
	case MYSQL_TYPE_DATETIME:
	case MYSQL_TYPE_TIMESTAMP:
		size = sizeof(MYSQL_TIME);
		break;
	default:
		size = field->length;
	}

	return size;
}

/*
 * num_affected_rows = statement:affected()
 */
static int statement_affected(lua_State *L)
{
	statement_t *statement = (statement_t *)luaL_checkudata(L, 1, EV_MYSQL_STATEMENT);

	if (!statement->stmt)
	{
		luaL_error(L, EV_SQL_ERR_INVALID_STATEMENT);
	}

	lua_pushinteger(L, mysql_stmt_affected_rows(statement->stmt));

	return 1;
}

static void vs_nr_func(void *i)
{
	return;
}

/*
 * cleanup function in use
 */
static void vs_nr_statement_close(void *v)
{
	statement_t *statement = (statement_t *)v;

	mysql_free_result(statement->metadata);
	statement->metadata = NULL;

	free(statement->lengths);
	statement->lengths = NULL;

	mysql_stmt_close(statement->stmt);
	int ok = 1;
	statement->stmt = NULL;

	free(statement);
	statement = NULL;

	return;
}

static void *vs_statement_close(void *v)
{
	generic_task_params_ptr_t iparams = (generic_task_params_ptr_t)v;
	// DEBUGPOINT("vs_statement_close() for %p\n", getL(iparams));
	statement_t *statement = (statement_t *)get_generic_task_ptr_param(iparams, 1);
	// DEBUGPOINT("Here udata of statement = %p\n", statement);

	mysql_free_result(statement->metadata);
	statement->metadata = NULL;

	free(statement->lengths);
	statement->lengths = NULL;

	mysql_stmt_close(statement->stmt);
	int ok = 1;
	statement->stmt = NULL;

	generic_task_params_ptr_t oparams = new_generic_task_params();
	set_lua_stack_out_param(oparams, EV_LUA_TBOOLEAN, &ok);

	iparams = destroy_generic_task_in_params(iparams);

	return oparams;
}

/*
 * success = statement:close()
 */
static int initiate_statement_close(lua_State *L)
{
	Poco::evnet::EVLHTTPRequestHandler *reqHandler = get_req_handler_instance(L);
	poco_assert(reqHandler != NULL);

	statement_t *statement = (statement_t *)luaL_checkudata(L, 1, EV_MYSQL_STATEMENT);

	if (!(statement->metadata))
	{
		lua_pushboolean(L, 0);
		return 1;
	}

	if (!(statement->lengths))
	{
		lua_pushboolean(L, 0);
		return 1;
	}

	if (!(statement->stmt))
	{
		lua_pushboolean(L, 0);
		return 1;
	}

	// DEBUGPOINT("Here udata of statement = %p\n", statement);
	generic_task_params_ptr_t params = pack_lua_stack_in_params(L);
	reqHandler->executeGenericTask(NULL, &vs_statement_close, params);
	return lua_yieldk(L, 0, (lua_KContext) "statement could not be closed", completion_common_routine);
}

static void *vs_statement_columns(void *v)
{
	generic_task_params_ptr_t iparams = (generic_task_params_ptr_t)v;
	statement_t *statement = (statement_t *)get_generic_task_ptr_param(iparams, 1);

	MYSQL_FIELD *fields;
	int i;
	int num_columns;
	int d = 1;

	fields = mysql_fetch_fields(statement->metadata);
	num_columns = mysql_num_fields(statement->metadata);

	evnet_lua_table_t *table = new evnet_lua_table_t();

	for (i = 0; i < num_columns; i++)
	{
		const char *name = fields[i].name;

		EVLUA_TABLE_PUSH_ARRAY_STRING(table, d, name);
	}

	generic_task_params_ptr_t oparams = new_generic_task_params();
	set_lua_stack_out_param(oparams, EV_LUA_TTABLE, table);

	iparams = destroy_generic_task_in_params(iparams);

	return oparams;
}

/*
 * column_names = statement:columns()
 */
static int initiate_statement_columns(lua_State *L)
{

	Poco::evnet::EVLHTTPRequestHandler *reqHandler = get_req_handler_instance(L);
	poco_assert(reqHandler != NULL);

	statement_t *statement = (statement_t *)luaL_checkudata(L, 1, EV_MYSQL_STATEMENT);

	MYSQL_FIELD *fields;
	int i;
	int num_columns;
	int d = 1;

	if (!statement->stmt)
	{
		luaL_error(L, EV_SQL_ERR_INVALID_STATEMENT);
		return 0;
	}

	generic_task_params_ptr_t params = pack_lua_stack_in_params(L);
	reqHandler->executeGenericTask(NULL, &vs_statement_columns, params);
	return lua_yieldk(L, 0, (lua_KContext) "statement columns could not be fetched", completion_common_routine);
}

static void *vs_statement_execute(void *v)
{
	generic_task_params_ptr_t iparams = (generic_task_params_ptr_t)v;
	statement_t *statement = (statement_t *)get_generic_task_ptr_param(iparams, 1);

	int n = get_num_generic_params(iparams);

	generic_task_params_ptr_t oparams = new_generic_task_params();

	int num_bind_params = n - 1;
	int expected_params;

	unsigned char *buffer = NULL;
	int offset = 0;

	MYSQL_BIND *bind = NULL;
	MYSQL_RES *metadata = NULL;

	char *error_message = NULL;
	char *errstr = NULL;

	int p;

	int zero = 0;
	int one = 1;

	/*
	 * Sanity check(s)
	 */
	if (statement->conn->mysql == NULL)
	{
		set_lua_stack_out_param(oparams, EV_LUA_TSTRING, (char *)EV_SQL_ERR_STATEMENT_BROKEN);
		// lua_error(L); ----------------------------------------> Here
	}

	if (statement->metadata)
	{
		/*
		 * free existing metadata from any previous executions
		 */
		mysql_free_result(statement->metadata);
		statement->metadata = NULL;
	}

	expected_params = mysql_stmt_param_count(statement->stmt);

	if (expected_params != num_bind_params)
	{
		/*
		 * mysql_stmt_bind_param does not handle this condition,
		 * and the client library will segfault if these do no match
		 */
		set_lua_stack_out_param(oparams, EV_LUA_TBOOLEAN, &zero);
		char str[1024];
		sprintf(str, EV_SQL_ERR_PARAM_MISCOUNT, expected_params, num_bind_params);
		set_lua_stack_out_param(oparams, EV_LUA_TSTRING, str);
		return oparams;
	}

	if (num_bind_params > 0)
	{
		bind = (MYSQL_BIND *)malloc(sizeof(MYSQL_BIND) * num_bind_params);
		if (bind == NULL)
		{
			char err[] = "Could not alloc bind params\n";
			set_lua_stack_out_param(oparams, EV_LUA_TSTRING, err);
		}

		buffer = (unsigned char *)malloc(num_bind_params * sizeof(double));
		memset(bind, 0, sizeof(MYSQL_BIND) * num_bind_params);
	}

	for (p = 2; p <= n; p++)
	{
		int type = get_generic_task_param_type(iparams, p);
		int i = p - 2;

		const char *str = NULL;
		size_t *str_len = NULL;
		double *num = NULL;
		int *boolean = NULL;
		char err[64];

		switch (type)
		{
		case LUA_TNIL:
		{
			bind[i].buffer_type = MYSQL_TYPE_NULL;
			bind[i].is_null = (my_bool *)1;
			break;
		}
		case LUA_TBOOLEAN:
		{
			boolean = (int *)(buffer + offset);
			offset += sizeof(int);
			boolean = (int *)get_generic_task_ptr_param(iparams, p);

			bind[i].buffer_type = MYSQL_TYPE_LONG;
			bind[i].is_null = (my_bool *)0;
			bind[i].buffer = (char *)boolean;
			bind[i].length = 0;
			break;
		}
		case LUA_TNUMBER:
		{
			num = (double *)(buffer + offset);
			offset += sizeof(double);
			num = (double *)get_generic_task_ptr_param(iparams, p);

			bind[i].buffer_type = MYSQL_TYPE_DOUBLE;
			bind[i].is_null = (my_bool *)0;
			bind[i].buffer = (char *)num;
			bind[i].length = 0;
			break;
		}
		case LUA_TSTRING:
		{
			str_len = (size_t *)(buffer + offset);
			offset += sizeof(size_t);
			str = (char *)get_generic_task_ptr_param(iparams, p);

			bind[i].buffer_type = MYSQL_TYPE_STRING;
			bind[i].is_null = (my_bool *)0;
			bind[i].buffer = (char *)str;
			bind[i].length = str_len;
			break;
		}
		default:
		{
			/*
			 * Unknown/unsupported value type
			 */
			snprintf(err, sizeof(err) - 1, EV_SQL_ERR_BINDING_TYPE_ERR, get_generic_task_param_type(iparams, type));
			errstr = err;
			error_message = EV_SQL_ERR_BINDING_PARAMS;
			goto cleanup;
		}
		}
	}

	if (mysql_stmt_bind_param(statement->stmt, bind))
	{
		error_message = EV_SQL_ERR_BINDING_PARAMS;
		goto cleanup;
	}

	if (mysql_stmt_execute(statement->stmt))
	{
		error_message = EV_SQL_ERR_BINDING_EXEC;
		goto cleanup;
	}

	metadata = mysql_stmt_result_metadata(statement->stmt);

	if (metadata)
	{
		mysql_stmt_store_result(statement->stmt);
	}

cleanup:
	if (bind)
	{
		free(bind);
	}

	if (buffer)
	{
		free(buffer);
	}

	if (error_message)
	{
		set_lua_stack_out_param(oparams, EV_LUA_TBOOLEAN, &zero);
		char str[1024];
		sprintf(str, error_message, errstr ? errstr : mysql_stmt_error(statement->stmt));
		set_lua_stack_out_param(oparams, EV_LUA_TSTRING, str);
		return oparams;
	}

	statement->metadata = metadata;

	iparams = destroy_generic_task_in_params(iparams);
	set_lua_stack_out_param(oparams, EV_LUA_TBOOLEAN, &one);

	// DEBUGPOINT("Here\n");
	return oparams;
}

/*
 * success,err = statement:execute(...)
 */
static int initiate_statement_execute(lua_State *L)
{
	Poco::evnet::EVLHTTPRequestHandler *reqHandler = get_req_handler_instance(L);
	// DEBUGPOINT("initiate_statement_execute() for %d\n", reqHandler->getAccSockfd());
	statement_t *statement = (statement_t *)luaL_checkudata(L, 1, EV_MYSQL_STATEMENT);

	if (!statement->stmt)
	{
		lua_pushboolean(L, 0);
		lua_pushstring(L, EV_SQL_ERR_EXECUTE_INVALID);
		return 2;
	}

	// DEBUGPOINT("Here\n");
	generic_task_params_ptr_t params = pack_lua_stack_in_params(L);
	poco_assert(reqHandler != NULL);
	// DEBUGPOINT("Here for %d\n", reqHandler->getAccSockfd());
	reqHandler->executeGenericTask(NULL, &vs_statement_execute, params);
	return lua_yieldk(L, 0, (lua_KContext) "statement could not be executed", completion_common_routine);
}

static int statement_fetch_impl(lua_State *L, statement_t *statement, int named_columns)
{
	int column_count, fetch_result_ok;
	MYSQL_BIND *bind = NULL;
	const char *error_message = NULL;

	if (!statement->stmt)
	{
		luaL_error(L, EV_SQL_ERR_FETCH_INVALID);
		return 0;
	}

	if (!statement->metadata)
	{
		luaL_error(L, EV_SQL_ERR_FETCH_NO_EXECUTE);
		return 0;
	}

	column_count = mysql_num_fields(statement->metadata);

	if (column_count > 0)
	{
		int i;
		MYSQL_FIELD *fields;

		if (statement->lengths)
		{
			free(statement->lengths);
			statement->lengths = NULL;
		}

		statement->lengths = (unsigned long *)calloc(column_count, sizeof(unsigned long));

		bind = (MYSQL_BIND *)malloc(sizeof(MYSQL_BIND) * column_count);
		memset(bind, 0, sizeof(MYSQL_BIND) * column_count);

		fields = mysql_fetch_fields(statement->metadata);

		for (i = 0; i < column_count; i++)
		{
			unsigned int length = mysql_buffer_size(&fields[i]);
			if (length > sizeof(MYSQL_TIME))
			{
				bind[i].buffer = NULL;
				bind[i].buffer_length = 0;
			}
			else
			{
				char *buffer = (char *)malloc(length);
				memset(buffer, 0, length);

				bind[i].buffer = buffer;
				bind[i].buffer_length = length;
			}

			bind[i].buffer_type = fields[i].type;
			bind[i].length = &(statement->lengths[i]);
		}

		if (mysql_stmt_bind_result(statement->stmt, bind))
		{
			error_message = EV_SQL_ERR_BINDING_RESULTS;
			goto cleanup;
		}

		fetch_result_ok = mysql_stmt_fetch(statement->stmt);
		if (fetch_result_ok == 0 || fetch_result_ok == MYSQL_DATA_TRUNCATED)
		{
			int d = 1;

			lua_newtable(L);
			for (i = 0; i < column_count; i++)
			{
				lua_push_type_t lua_push = mysql_to_lua_push(fields[i].type);
				const char *name = fields[i].name;

				if (bind[i].buffer == NULL)
				{
					char *buffer = (char *)calloc(statement->lengths[i] + 1, sizeof(char));
					bind[i].buffer = buffer;
					bind[i].buffer_length = statement->lengths[i];
					mysql_stmt_fetch_column(statement->stmt, &bind[i], i, 0);
				}

				if (lua_push == LUA_PUSH_NIL)
				{
					if (named_columns)
					{
						LUA_PUSH_ATTRIB_NIL(name);
					}
					else
					{
						LUA_PUSH_ARRAY_NIL(d);
					}
				}
				else if (lua_push == LUA_PUSH_INTEGER)
				{
					if (fields[i].type == MYSQL_TYPE_YEAR || fields[i].type == MYSQL_TYPE_SHORT)
					{
						if (named_columns)
						{
							LUA_PUSH_ATTRIB_INT(name, *(short *)(bind[i].buffer));
						}
						else
						{
							LUA_PUSH_ARRAY_INT(d, *(short *)(bind[i].buffer));
						}
					}
					else if (fields[i].type == MYSQL_TYPE_TINY)
					{
						if (named_columns)
						{
							LUA_PUSH_ATTRIB_INT(name, (int)*(char *)(bind[i].buffer));
						}
						else
						{
							LUA_PUSH_ARRAY_INT(d, (int)*(char *)(bind[i].buffer));
						}
					}
					else
					{
						if (named_columns)
						{
							LUA_PUSH_ATTRIB_INT(name, *(int *)(bind[i].buffer));
						}
						else
						{
							LUA_PUSH_ARRAY_INT(d, *(int *)(bind[i].buffer));
						}
					}
				}
				else if (lua_push == LUA_PUSH_NUMBER)
				{
					if (fields[i].type == MYSQL_TYPE_FLOAT)
					{
						if (named_columns)
						{
							LUA_PUSH_ATTRIB_FLOAT(name, *(float *)(bind[i].buffer));
						}
						else
						{
							LUA_PUSH_ARRAY_FLOAT(d, *(float *)(bind[i].buffer));
						}
					}
					else if (fields[i].type == MYSQL_TYPE_DOUBLE)
					{
						if (named_columns)
						{
							LUA_PUSH_ATTRIB_FLOAT(name, *(double *)(bind[i].buffer));
						}
						else
						{
							LUA_PUSH_ARRAY_FLOAT(d, *(double *)(bind[i].buffer));
						}
					}
					else
					{
						if (named_columns)
						{
							LUA_PUSH_ATTRIB_FLOAT(name, *(long long *)(bind[i].buffer));
						}
						else
						{
							LUA_PUSH_ARRAY_FLOAT(d, *(long long *)(bind[i].buffer));
						}
					}
				}
				else if (lua_push == LUA_PUSH_STRING)
				{

					if (fields[i].type == MYSQL_TYPE_TIMESTAMP || fields[i].type == MYSQL_TYPE_DATETIME)
					{
						char str[20];
						MYSQL_TIME *t = (MYSQL_TIME *)bind[i].buffer;

						snprintf(str, 20, "%d-%02d-%02d %02d:%02d:%02d", t->year, t->month, t->day, t->hour, t->minute, t->second);

						if (named_columns)
						{
							LUA_PUSH_ATTRIB_STRING(name, str);
						}
						else
						{
							LUA_PUSH_ARRAY_STRING(d, str);
						}
					}
					else if (fields[i].type == MYSQL_TYPE_TIME)
					{
						char str[9];
						MYSQL_TIME *t = (MYSQL_TIME *)bind[i].buffer;

						snprintf(str, 9, "%02d:%02d:%02d", t->hour, t->minute, t->second);

						if (named_columns)
						{
							LUA_PUSH_ATTRIB_STRING(name, str);
						}
						else
						{
							LUA_PUSH_ARRAY_STRING(d, str);
						}
					}
					else if (fields[i].type == MYSQL_TYPE_DATE)
					{
						char str[20];
						MYSQL_TIME *t = (MYSQL_TIME *)bind[i].buffer;

						snprintf(str, 11, "%d-%02d-%02d", t->year, t->month, t->day);

						if (named_columns)
						{
							LUA_PUSH_ATTRIB_STRING(name, str);
						}
						else
						{
							LUA_PUSH_ARRAY_STRING(d, str);
						}
					}
					else
					{
						if (named_columns)
						{
							LUA_PUSH_ATTRIB_STRING_BY_LENGTH(name, (const char *)bind[i].buffer, *bind[i].length);
						}
						else
						{
							LUA_PUSH_ARRAY_STRING_BY_LENGTH(d, (const char *)bind[i].buffer, *bind[i].length);
						}
					}
				}
				else if (lua_push == LUA_PUSH_BOOLEAN)
				{
					if (named_columns)
					{
						LUA_PUSH_ATTRIB_BOOL(name, *(int *)(bind[i].buffer));
					}
					else
					{
						LUA_PUSH_ARRAY_BOOL(d, *(int *)(bind[i].buffer));
					}
				}
				else
				{
					luaL_error(L, EV_SQL_ERR_UNKNOWN_PUSH);
				}
			}
		}
		else
		{
			lua_pushnil(L);
		}
	}

cleanup:

	if (bind)
	{
		int i;

		for (i = 0; i < column_count; i++)
		{
			free(bind[i].buffer);
		}

		free(bind);
	}

	if (error_message)
	{
		luaL_error(L, error_message, mysql_stmt_error(statement->stmt));
		return 0;
	}

	return 1;
}

static void *vs_statement_fetch_impl(void *v)
{
	generic_task_params_ptr_t iparams = (generic_task_params_ptr_t)v;
	// DEBUGPOINT("vs_statement_close() for %p\n", getL(iparams));
	statement_t *statement = (statement_t *)get_generic_task_ptr_param(iparams, 1);
	// DEBUGPOINT("Here udata of statement = %p\n", statement);

	int *named_columns = (int *)get_generic_task_ptr_param(iparams, 2);

	int column_count, fetch_result_ok;
	MYSQL_BIND *bind = NULL;
	const char *error_message = NULL;

	column_count = mysql_num_fields(statement->metadata);

	generic_task_params_ptr_t oparams = new_generic_task_params();

	if (column_count > 0)
	{
		int i;
		MYSQL_FIELD *fields;

		if (statement->lengths)
		{
			free(statement->lengths);
			statement->lengths = NULL;
		}

		statement->lengths = (unsigned long *)calloc(column_count, sizeof(unsigned long));

		bind = (MYSQL_BIND *)malloc(sizeof(MYSQL_BIND) * column_count);
		memset(bind, 0, sizeof(MYSQL_BIND) * column_count);

		fields = mysql_fetch_fields(statement->metadata);

		for (i = 0; i < column_count; i++)
		{
			unsigned int length = mysql_buffer_size(&fields[i]);
			if (length > sizeof(MYSQL_TIME))
			{
				bind[i].buffer = NULL;
				bind[i].buffer_length = 0;
			}
			else
			{
				char *buffer = (char *)malloc(length);
				memset(buffer, 0, length);

				bind[i].buffer = buffer;
				bind[i].buffer_length = length;
			}

			bind[i].buffer_type = fields[i].type;
			bind[i].length = &(statement->lengths[i]);
		}

		if (mysql_stmt_bind_result(statement->stmt, bind))
		{
			error_message = EV_SQL_ERR_BINDING_RESULTS;
			goto cleanup;
		}

		fetch_result_ok = mysql_stmt_fetch(statement->stmt);
		if (fetch_result_ok == 0 || fetch_result_ok == MYSQL_DATA_TRUNCATED)
		{
			int d = 1;

			// lua_newtable(L);
			evnet_lua_table_t *table = new evnet_lua_table_t();

			for (i = 0; i < column_count; i++)
			{
				lua_push_type_t lua_push = mysql_to_lua_push(fields[i].type);
				const char *name = fields[i].name;

				if (bind[i].buffer == NULL)
				{
					char *buffer = (char *)calloc(statement->lengths[i] + 1, sizeof(char));
					bind[i].buffer = buffer;
					bind[i].buffer_length = statement->lengths[i];
					mysql_stmt_fetch_column(statement->stmt, &bind[i], i, 0);
				}

				if (lua_push == LUA_PUSH_NIL)
				{
					if (named_columns)
					{
						EVLUA_TABLE_PUSH_ATTRIB_NIL(table, name);
					}
					else
					{
						EVLUA_TABLE_PUSH_ARRAY_NIL(table, d);
					}
				}
				else if (lua_push == LUA_PUSH_INTEGER)
				{
					if (fields[i].type == MYSQL_TYPE_YEAR || fields[i].type == MYSQL_TYPE_SHORT)
					{
						if (named_columns)
						{
							EVLUA_TABLE_PUSH_ATTRIB_INT(table, name, *(short *)(bind[i].buffer));
						}
						else
						{
							EVLUA_TABLE_PUSH_ARRAY_INT(table, d, *(short *)(bind[i].buffer));
						}
					}
					else if (fields[i].type == MYSQL_TYPE_TINY)
					{
						if (named_columns)
						{
							EVLUA_TABLE_PUSH_ATTRIB_INT(table, name, (int)*(char *)(bind[i].buffer));
						}
						else
						{
							EVLUA_TABLE_PUSH_ARRAY_INT(table, d, (int)*(char *)(bind[i].buffer));
						}
					}
					else
					{
						if (named_columns)
						{
							EVLUA_TABLE_PUSH_ATTRIB_INT(table, name, *(int *)(bind[i].buffer));
						}
						else
						{
							EVLUA_TABLE_PUSH_ARRAY_INT(table, d, *(int *)(bind[i].buffer));
						}
					}
				}
				else if (lua_push == LUA_PUSH_NUMBER)
				{
					if (fields[i].type == MYSQL_TYPE_FLOAT)
					{
						if (named_columns)
						{
							EVLUA_TABLE_PUSH_ATTRIB_FLOAT(table, name, *(float *)(bind[i].buffer));
						}
						else
						{
							EVLUA_TABLE_PUSH_ARRAY_FLOAT(table, d, *(float *)(bind[i].buffer));
						}
					}
					else if (fields[i].type == MYSQL_TYPE_DOUBLE)
					{
						if (named_columns)
						{
							EVLUA_TABLE_PUSH_ATTRIB_FLOAT(table, name, *(double *)(bind[i].buffer));
						}
						else
						{
							EVLUA_TABLE_PUSH_ARRAY_FLOAT(table, d, *(double *)(bind[i].buffer));
						}
					}
					else
					{
						if (named_columns)
						{
							EVLUA_TABLE_PUSH_ATTRIB_FLOAT(table, name, *(long long *)(bind[i].buffer));
						}
						else
						{
							EVLUA_TABLE_PUSH_ARRAY_FLOAT(table, d, *(long long *)(bind[i].buffer));
						}
					}
				}
				else if (lua_push == LUA_PUSH_STRING)
				{

					if (fields[i].type == MYSQL_TYPE_TIMESTAMP || fields[i].type == MYSQL_TYPE_DATETIME)
					{
						char str[20];
						MYSQL_TIME *t = (MYSQL_TIME *)bind[i].buffer;

						snprintf(str, 20, "%d-%02d-%02d %02d:%02d:%02d", t->year, t->month, t->day, t->hour, t->minute, t->second);

						if (named_columns)
						{
							EVLUA_TABLE_PUSH_ATTRIB_STRING(table, name, str);
						}
						else
						{
							EVLUA_TABLE_PUSH_ARRAY_STRING(table, d, str);
						}
					}
					else if (fields[i].type == MYSQL_TYPE_TIME)
					{
						char str[9];
						MYSQL_TIME *t = (MYSQL_TIME *)bind[i].buffer;

						snprintf(str, 9, "%02d:%02d:%02d", t->hour, t->minute, t->second);

						if (named_columns)
						{
							EVLUA_TABLE_PUSH_ATTRIB_STRING(table, name, str);
						}
						else
						{
							EVLUA_TABLE_PUSH_ARRAY_STRING(table, d, str);
						}
					}
					else if (fields[i].type == MYSQL_TYPE_DATE)
					{
						char str[20];
						MYSQL_TIME *t = (MYSQL_TIME *)bind[i].buffer;

						snprintf(str, 11, "%d-%02d-%02d", t->year, t->month, t->day);

						if (named_columns)
						{
							EVLUA_TABLE_PUSH_ATTRIB_STRING(table, name, str);
						}
						else
						{
							EVLUA_TABLE_PUSH_ARRAY_STRING(table, d, str);
						}
					}
					else
					{
						if (named_columns)
						{
							EVLUA_TABLE_PUSH_ATTRIB_STRING_BY_LENGTH(table, name, (const char *)bind[i].buffer, *bind[i].length);
						}
						else
						{
							EVLUA_TABLE_PUSH_ARRAY_STRING_BY_LENGTH(table, d, (const char *)bind[i].buffer, *bind[i].length);
						}
					}
				}
				else if (lua_push == LUA_PUSH_BOOLEAN)
				{
					if (named_columns)
					{
						EVLUA_TABLE_PUSH_ATTRIB_BOOL(table, name, *(int *)(bind[i].buffer));
					}
					else
					{
						EVLUA_TABLE_PUSH_ARRAY_BOOL(table, d, *(int *)(bind[i].buffer));
					}
				}
				else
				{
					set_lua_stack_out_param(oparams, EV_LUA_TSTRING, (char *)EV_SQL_ERR_UNKNOWN_PUSH);
				}
			}
		}
		else
		{
			set_lua_stack_out_param(oparams, EV_LUA_TNIL, 0);
		}
	}

cleanup:

	if (bind)
	{
		int i;

		for (i = 0; i < column_count; i++)
		{
			free(bind[i].buffer);
		}

		free(bind);
	}

	if (error_message)
	{
		char str[1024];
		sprintf(str, error_message, mysql_stmt_error(statement->stmt));
		set_lua_stack_out_param(oparams, EV_LUA_TSTRING, str);
		return oparams;
	}

	iparams = destroy_generic_task_in_params(iparams);

	return oparams;
}

static int initiate_statement_fetch_impl(lua_State *L, statement_t *statement, int named_columns)
{
	Poco::evnet::EVLHTTPRequestHandler *reqHandler = get_req_handler_instance(L);
	poco_assert(reqHandler != NULL);
	// DEBUGPOINT("initiate_statement_fetch_impl() for %d\n", reqHandler->getAccSockfd());

	if (!statement->stmt)
	{
		luaL_error(L, EV_SQL_ERR_FETCH_INVALID);
		return 0;
	}

	if (!statement->metadata)
	{
		luaL_error(L, EV_SQL_ERR_FETCH_NO_EXECUTE);
		return 0;
	}

	generic_task_params_ptr_t params = pack_lua_stack_in_params(L);
	poco_assert(reqHandler != NULL);
	// DEBUGPOINT("Here for %d\n", reqHandler->getAccSockfd());
	reqHandler->executeGenericTask(NULL, &vs_statement_fetch_impl, params);
	return lua_yieldk(L, 0, (lua_KContext) "statement could not be fetched", completion_common_routine);
}

static int next_iterator(lua_State *L)
{
	statement_t *statement = (statement_t *)luaL_checkudata(L, lua_upvalueindex(1), EV_MYSQL_STATEMENT);
	int named_columns = lua_toboolean(L, lua_upvalueindex(2));

	return statement_fetch_impl(L, statement, named_columns);
	// return initiate_statement_fetch_impl(L, statement, named_columns);
}

/*
 * table = statement:fetch(named_indexes)
 */
static int statement_fetch(lua_State *L)
{
	statement_t *statement = (statement_t *)luaL_checkudata(L, 1, EV_MYSQL_STATEMENT);
	int named_columns = lua_toboolean(L, 2);

	return statement_fetch_impl(L, statement, named_columns);
	// return initiate_statement_fetch_impl(L, statement, named_columns);
}

/*
 * num_rows = statement:rowcount()
 */
static int statement_rowcount(lua_State *L)
{
	statement_t *statement = (statement_t *)luaL_checkudata(L, 1, EV_MYSQL_STATEMENT);

	if (!statement->stmt)
	{
		luaL_error(L, EV_SQL_ERR_INVALID_STATEMENT);
	}

	lua_pushinteger(L, mysql_stmt_num_rows(statement->stmt));

	return 1;
}

/*
 * iterfunc = statement:rows(named_indexes)
 */
static int statement_rows(lua_State *L)
{
	if (lua_gettop(L) == 1)
	{
		lua_pushvalue(L, 1);
		lua_pushboolean(L, 0);
	}
	else
	{
		lua_pushvalue(L, 1);
		lua_pushboolean(L, lua_toboolean(L, 2));
	}

	lua_pushcclosure(L, next_iterator, 2);
	return 1;
}

/*
 * __gc
 */
static int new_statement_gc(lua_State *L)
{
	Poco::evnet::EVLHTTPRequestHandler *reqHandler = get_req_handler_instance(L);
	poco_assert(reqHandler != NULL);

	statement_t *l_statement = (statement_t *)luaL_checkudata(L, 1, EV_MYSQL_STATEMENT);

	if (!(l_statement->metadata))
	{
		lua_pushboolean(L, 0);
		return 1;
	}

	if (!(l_statement->lengths))
	{
		lua_pushboolean(L, 0);
		return 1;
	}

	if (!(l_statement->stmt))
	{
		lua_pushboolean(L, 0);
		return 1;
	}

	statement_t *statement = NULL;
	statement = (statement_t *)malloc(sizeof(statement_t));
	memcpy(statement, l_statement, sizeof(statement_t));

	vs_nr_statement_close(statement);

	return 0;
}

/*
 * __tostring
 */
static int statement_tostring(lua_State *L)
{
	statement_t *statement = (statement_t *)luaL_checkudata(L, 1, EV_MYSQL_STATEMENT);

	lua_pushfstring(L, "%s: %p", EV_MYSQL_STATEMENT, statement);

	return 1;
}

extern "C" void ev_mysql_statement_create(generic_task_params_ptr_t iparams, generic_task_params_ptr_t oparams, connection_t *conn, const char *sql_query);
void ev_mysql_statement_create(generic_task_params_ptr_t iparams, generic_task_params_ptr_t oparams, connection_t *conn, const char *sql_query)
{

	unsigned long sql_len = strlen(sql_query);

	statement_t *statement = NULL;

	MYSQL_STMT *stmt = mysql_stmt_init(conn->mysql);

	if (!stmt)
	{
		set_lua_stack_out_param(oparams, EV_LUA_TNIL, 0);
		char str[1024];
		sprintf(str, EV_SQL_ERR_ALLOC_STATEMENT, mysql_error(conn->mysql));
		set_lua_stack_out_param(oparams, EV_LUA_TSTRING, str);
		return;
	}

	if (mysql_stmt_prepare(stmt, sql_query, sql_len))
	{
		set_lua_stack_out_param(oparams, EV_LUA_TNIL, 0);
		char str[1024];
		sprintf(str, EV_SQL_ERR_PREP_STATEMENT, mysql_stmt_error(stmt));
		set_lua_stack_out_param(oparams, EV_LUA_TSTRING, str);
		return;
	}

	statement = (statement_t *)malloc(sizeof(statement_t));
	statement->conn = conn;
	statement->stmt = stmt;
	statement->metadata = NULL;
	statement->lengths = NULL;

	set_lua_stack_out_param(oparams, EV_LUA_TUSERDATA, get_generic_lua_userdata(EV_MYSQL_STATEMENT, statement, sizeof(statement_t)));

	return;
}

extern "C" int ev_mysql_statement(lua_State *L);
int ev_mysql_statement(lua_State *L)
{
	static const luaL_Reg statement_methods[] = {
		{"affected", statement_affected},		 // Done
		{"close", initiate_statement_close},	 // Done
		{"columns", initiate_statement_columns}, // Done
		{"execute", initiate_statement_execute}, // Done
		{"fetch", statement_fetch},
		{"rowcount", statement_rowcount}, // Done
		{"rows", statement_rows},
		{NULL, NULL}};

	static const luaL_Reg statement_class_methods[] = {
		{NULL, NULL}};

	ev_sql_register(L, EV_MYSQL_STATEMENT,
					statement_methods, statement_class_methods,
					new_statement_gc, statement_tostring); // Done

	return 1;
}
