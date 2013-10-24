
#include "ngx_tcp_lua_common.h"
#include "ngx_tcp_lua_util.h"
#include "ngx_tcp_lua_output.h"


static int ngx_tcp_lua_ngx_print(lua_State *L);


static int
ngx_tcp_lua_ngx_print(lua_State *L)
{
    dd("calling lua print");
    return ngx_tcp_lua_ngx_echo(L, 0,1);
}


static int
ngx_tcp_lua_ngx_say(lua_State *L)
{
    dd("calling");
    return ngx_tcp_lua_ngx_echo(L, 1,1);
}


int
ngx_tcp_lua_ngx_echo(lua_State *L, unsigned newline,unsigned start)
{
    ngx_tcp_session_t          *s;
    ngx_tcp_lua_ctx_t          *ctx;
    const char                  *p;
    size_t                       len;
    size_t                       size;
    ngx_buf_t                   *b;
    ngx_chain_t                 *cl, *chain;
    int                          i;
    int                          nargs;
    int                          type;
    const char                  *msg;
    //ngx_buf_tag_t                tag;

    lua_pushlightuserdata(L, &ngx_tcp_lua_request_key);
    lua_rawget(L, LUA_GLOBALSINDEX);
    s = lua_touserdata(L, -1);
    lua_pop(L, 1);

    if (s == NULL) {
        return luaL_error(L, "no request object found");
    }

    ctx = ngx_tcp_get_module_ctx(s, ngx_tcp_lua_module);

    if (ctx == NULL) {
        return luaL_error(L, "no request ctx found");
    }

/*
    if (ctx->eof) {
        return luaL_error(L, "seen eof already");
    }
*/
    nargs = lua_gettop(L);
    size = 0;

    for (i = start; i <= nargs; i++) {

        type = lua_type(L, i);

        switch (type) {
            case LUA_TNUMBER:
            case LUA_TSTRING:

                lua_tolstring(L, i, &len);
                size += len;
                break;

            case LUA_TNIL:

                size += sizeof("nil") - 1;
                break;

            case LUA_TBOOLEAN:

                if (lua_toboolean(L, i)) {
                    size += sizeof("true") - 1;

                } else {
                    size += sizeof("false") - 1;
                }

                break;

            case LUA_TTABLE:

                size += ngx_tcp_lua_calc_strlen_in_table(L, i, 0);
                break;

            case LUA_TLIGHTUSERDATA:

                dd("userdata: %p", lua_touserdata(L, i));

                if (lua_touserdata(L, i) == NULL) {
                    size += sizeof("null") - 1;
                    break;
                }

                continue;

            default:

                msg = lua_pushfstring(L, "string, number, boolean, nil, "
                                      "ngx.null, or array table expected, "
                                      "but got %s", lua_typename(L, type));

                return luaL_argerror(L, i, msg);
        }
    }

    if (newline) {
        size += sizeof("\n") - 1;
    }

    if (size == 0) {
        /* do nothing for empty strings */
        return 0;
    }

    b = ngx_create_temp_buf(s->pool, size);
    if (b == NULL) {
        return luaL_error(L, "out of memory");
    }

    for (i = start; i <= nargs; i++) {
        type = lua_type(L, i);
        switch (type) {
            case LUA_TNUMBER:
            case LUA_TSTRING:
                p = lua_tolstring(L, i, &len);
                b->last = ngx_copy(b->last, (u_char *) p, len);
                break;

            case LUA_TNIL:
                *b->last++ = 'n';
                *b->last++ = 'i';
                *b->last++ = 'l';
                break;

            case LUA_TBOOLEAN:
                if (lua_toboolean(L, i)) {
                    *b->last++ = 't';
                    *b->last++ = 'r';
                    *b->last++ = 'u';
                    *b->last++ = 'e';

                } else {
                    *b->last++ = 'f';
                    *b->last++ = 'a';
                    *b->last++ = 'l';
                    *b->last++ = 's';
                    *b->last++ = 'e';
                }

                break;

            case LUA_TTABLE:
                //b->last = ngx_tcp_lua_copy_str_in_table(L, i, b->last);
                break;

            case LUA_TLIGHTUSERDATA:
                *b->last++ = 'n';
                *b->last++ = 'u';
                *b->last++ = 'l';
                *b->last++ = 'l';
                break;

            default:
                return luaL_error(L, "impossible to reach here");
        }
    }

    if (newline) {
        *b->last++ = '\n';
    }

#if 0
    if (b->last != b->end) {
        return luaL_error(L, "buffer error: %p != %p", b->last, b->end);
    }
#endif

    cl = ngx_alloc_chain_link(s->pool);
    if (cl == NULL) {
        return luaL_error(L, "out of memory");
    }

    cl->next = NULL;
    cl->buf = b;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, s->connection->log, 0,
                   newline ? "lua say response" : "lua print response");
                   
    chain = s->connection->send_chain(s->connection, cl, 0);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0,
                  "tcp_lua write chain %p", chain);
    
    return 0;
}

int
ngx_tcp_lua_ngx_exit(lua_State *L)
{
    ngx_tcp_session_t          *s;
    ngx_tcp_lua_ctx_t          *ctx;
    //ngx_buf_tag_t                tag;

    lua_pushlightuserdata(L, &ngx_tcp_lua_request_key);
    lua_rawget(L, LUA_GLOBALSINDEX);
    s = lua_touserdata(L, -1);
    lua_pop(L, 1);

    if (s == NULL) {
        return luaL_error(L, "no request object found");
    }

    ctx = ngx_tcp_get_module_ctx(s, ngx_tcp_lua_module);

    if (ctx == NULL) {
        return luaL_error(L, "no request ctx found");
    }
	ctx->exited = 1;

    
    return lua_yield(L,0);
}

void
ngx_tcp_lua_inject_output_api(lua_State *L)
{
    lua_pushcfunction(L, ngx_tcp_lua_ngx_say);
    lua_setfield(L, -2, "say");

    lua_pushcfunction(L, ngx_tcp_lua_ngx_print);
    lua_setfield(L, -2, "print");

    lua_pushcfunction(L, ngx_tcp_lua_ngx_exit);
    lua_setfield(L, -2, "exit");

}


size_t
ngx_tcp_lua_calc_strlen_in_table(lua_State *L, int arg_i, unsigned strict)
{
    double              key;
    int                 max;
    int                 i;
    int                 type;
    size_t              size;
    size_t              len;
    const char         *msg;

    max = 0;

    lua_pushnil(L); /* stack: table key */
    while (lua_next(L, -2) != 0) { /* stack: table key value */
        if (lua_type(L, -2) == LUA_TNUMBER && (key = lua_tonumber(L, -2))) {
            if (floor(key) == key && key >= 1) {
                if (key > max) {
                    max = key;
                }

                lua_pop(L, 1); /* stack: table key */
                continue;
            }
        }

        /* not an array (non positive integer key) */
        lua_pop(L, 2); /* stack: table */

        msg = lua_pushfstring(L, "non-array table found");
        luaL_argerror(L, arg_i, msg);
        return 0;
    }

    size = 0;

    for (i = 1; i <= max; i++) {
        lua_rawgeti(L, -1, i); /* stack: table value */
        type = lua_type(L, -1);

        switch (type) {
            case LUA_TNUMBER:
            case LUA_TSTRING:

                lua_tolstring(L, -1, &len);
                size += len;
                break;

            case LUA_TNIL:

                if (strict) {
                    goto bad_type;
                }

                size += sizeof("nil") - 1;
                break;

            case LUA_TBOOLEAN:

                if (strict) {
                    goto bad_type;
                }

                if (lua_toboolean(L, -1)) {
                    size += sizeof("true") - 1;

                } else {
                    size += sizeof("false") - 1;
                }

                break;

            case LUA_TTABLE:

                size += ngx_tcp_lua_calc_strlen_in_table(L, arg_i, strict);
                break;

            case LUA_TLIGHTUSERDATA:

                if (strict) {
                    goto bad_type;
                }

                if (lua_touserdata(L, -1) == NULL) {
                    size += sizeof("null") - 1;
                    break;
                }

                continue;

            default:

bad_type:
                msg = lua_pushfstring(L, "bad data type %s found",
                        lua_typename(L, type));
                return luaL_argerror(L, arg_i, msg);
        }

        lua_pop(L, 1); /* stack: table */
    }

    return size;
}


u_char *
ngx_tcp_lua_copy_str_in_table(lua_State *L, u_char *dst)
{
    double               key;
    int                  max;
    int                  i;
    int                  type;
    size_t               len;
    u_char              *p;

    max = 0;

    lua_pushnil(L); /* stack: table key */
    while (lua_next(L, -2) != 0) { /* stack: table key value */
        key = lua_tonumber(L, -2);
        if (key > max) {
            max = key;
        }

        lua_pop(L, 1); /* stack: table key */
    }

    for (i = 1; i <= max; i++) {
        lua_rawgeti(L, -1, i); /* stack: table value */
        type = lua_type(L, -1);
        switch (type) {
            case LUA_TNUMBER:
            case LUA_TSTRING:
                p = (u_char *) lua_tolstring(L, -1, &len);
                dst = ngx_copy(dst, p, len);
                break;

            case LUA_TNIL:
                *dst++ = 'n';
                *dst++ = 'i';
                *dst++ = 'l';
                break;

            case LUA_TBOOLEAN:
                if (lua_toboolean(L, -1)) {
                    *dst++ = 't';
                    *dst++ = 'r';
                    *dst++ = 'u';
                    *dst++ = 'e';

                } else {
                    *dst++ = 'f';
                    *dst++ = 'a';
                    *dst++ = 'l';
                    *dst++ = 's';
                    *dst++ = 'e';
                }

                break;

            case LUA_TTABLE:
                dst = ngx_tcp_lua_copy_str_in_table(L, dst);
                break;

            case LUA_TLIGHTUSERDATA:

                *dst++ = 'n';
                *dst++ = 'u';
                *dst++ = 'l';
                *dst++ = 'l';
                break;

            default:
                luaL_error(L, "impossible to reach here");
                return NULL;
        }

        lua_pop(L, 1); /* stack: table */
    }

    return dst;
}



