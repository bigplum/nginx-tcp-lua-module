
#include "ngx_tcp_lua_common.h"
#include "ngx_tcp_lua_util.h"


static int ngx_tcp_lua_ngx_echo(lua_State *L, unsigned newline);


static int
ngx_tcp_lua_ngx_print(lua_State *L)
{
    dd("calling lua print");
    return ngx_tcp_lua_ngx_echo(L, 0);
}


static int
ngx_tcp_lua_ngx_echo(lua_State *L, unsigned newline)
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

    for (i = 1; i <= nargs; i++) {

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
//todo
                //size += ngx_tcp_lua_calc_strlen_in_table(L, i, i,
                //                                          0 /* strict */);
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

    for (i = 1; i <= nargs; i++) {
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

    if (b->last != b->end) {
        return luaL_error(L, "buffer error: %p != %p", b->last, b->end);
    }

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


void
ngx_tcp_lua_inject_output_api(lua_State *L)
{

    lua_pushcfunction(L, ngx_tcp_lua_ngx_print);
    lua_setfield(L, -2, "print");

}


