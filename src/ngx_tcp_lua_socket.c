

#include "ngx_tcp_lua_socket.h"
#include "ngx_tcp_lua_util.h"


#define NGX_TCP_LUA_SOCKET_FT_ERROR        0x0001
#define NGX_TCP_LUA_SOCKET_FT_TIMEOUT      0x0002
#define NGX_TCP_LUA_SOCKET_FT_CLOSED       0x0004
#define NGX_TCP_LUA_SOCKET_FT_RESOLVER     0x0008
#define NGX_TCP_LUA_SOCKET_FT_BUFTOOSMALL  0x0010
#define NGX_TCP_LUA_SOCKET_FT_NOMEM        0x0020

enum {
    SOCKET_CTX_INDEX = 1,
    SOCKET_TIMEOUT_INDEX = 2,
    SOCKET_KEY_INDEX = 3
};

static char ngx_tcp_lua_req_socket_metatable_key;
static char ngx_tcp_lua_tcp_socket_metatable_key;


static int ngx_tcp_lua_socket_error_retval_handler(ngx_tcp_session_t *s,
    ngx_tcp_lua_socket_upstream_t *u, lua_State *L);
static int ngx_tcp_lua_socket_tcp(lua_State *L);
static int ngx_tcp_lua_socket_tcp_receive(lua_State *L);
static ngx_int_t ngx_tcp_lua_socket_read_chunk(void *data, ssize_t bytes);
static ngx_int_t ngx_tcp_lua_socket_read_all(void *data, ssize_t bytes);
static ngx_int_t ngx_tcp_lua_socket_read_line(void *data, ssize_t bytes);
static ngx_int_t ngx_tcp_lua_socket_read(ngx_tcp_session_t *s,
    ngx_tcp_lua_socket_upstream_t *u);
static void ngx_tcp_lua_socket_read_handler(ngx_tcp_session_t *s,
    ngx_tcp_lua_socket_upstream_t *u);
static int ngx_tcp_lua_socket_tcp_receive_retval_handler(ngx_tcp_session_t *s,
    ngx_tcp_lua_socket_upstream_t *u, lua_State *L);
static void ngx_tcp_lua_socket_handle_success(ngx_tcp_session_t *s,
    ngx_tcp_lua_socket_upstream_t *u);
static void ngx_tcp_lua_socket_handle_error(ngx_tcp_session_t *s,
    ngx_tcp_lua_socket_upstream_t *u, ngx_uint_t ft_type);
static void ngx_tcp_lua_socket_finalize(ngx_tcp_session_t *r,
    ngx_tcp_lua_socket_upstream_t *u);
static int ngx_tcp_lua_req_socket(lua_State *L);
static int ngx_tcp_lua_req_socket(lua_State *L);
static void ngx_tcp_lua_req_socket_rev_handler(ngx_tcp_session_t *s);
static int ngx_tcp_lua_socket_downstream_destroy(lua_State *L);
static void ngx_tcp_lua_req_socket_cleanup(void *data);
static void ngx_tcp_lua_socket_dummy_handler(ngx_tcp_session_t *s,
    ngx_tcp_lua_socket_upstream_t *u);
static ngx_int_t ngx_tcp_lua_socket_add_input_buffer(ngx_tcp_session_t *s,
    ngx_tcp_lua_socket_upstream_t *u);
static ngx_int_t ngx_tcp_lua_socket_push_input_data(ngx_tcp_session_t *s,
    ngx_tcp_lua_ctx_t *ctx, ngx_tcp_lua_socket_upstream_t *u, lua_State *L);
static void ngx_tcp_lua_socket_free_pool(ngx_log_t *log,
    ngx_tcp_lua_socket_pool_t *spool);


void
ngx_tcp_lua_inject_socket_api(ngx_log_t *log, lua_State *L)
{
    ngx_int_t         rc;

    lua_createtable(L, 0, 2 /* nrec */);    /* ngx.socket */

    lua_pushcfunction(L, ngx_tcp_lua_socket_tcp);
    lua_setfield(L, -2, "tcp");

    {
        const char    buf[] = "local sock = ngx.socket.tcp()"
                   " local ok, err = sock:connect(...)"
                   " if ok then return sock else return nil, err end";

        rc = luaL_loadbuffer(L, buf, sizeof(buf) - 1, "ngx.socket.connect");
    }

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_CRIT, log, 0,
                      "failed to load Lua code for ngx.socket.connect(): %i",
                      rc);

    } else {
        lua_setfield(L, -2, "connect");
    }

    lua_setfield(L, -2, "socket");

    /* {{{req socket object metatable */
    lua_pushlightuserdata(L, &ngx_tcp_lua_req_socket_metatable_key);
    lua_createtable(L, 0 /* narr */, 4 /* nrec */);

    lua_pushcfunction(L, ngx_tcp_lua_socket_tcp_receive);
    lua_setfield(L, -2, "receive");

    lua_pushvalue(L, -1);
    lua_setfield(L, -2, "__index");

    lua_rawset(L, LUA_REGISTRYINDEX);
    /* }}} */

    /* {{{tcp object metatable */
    lua_pushlightuserdata(L, &ngx_tcp_lua_tcp_socket_metatable_key);
    lua_createtable(L, 0 /* narr */, 10 /* nrec */);

    lua_pushcfunction(L, ngx_tcp_lua_socket_tcp_receive);
    lua_setfield(L, -2, "receive");

    lua_pushvalue(L, -1);
    lua_setfield(L, -2, "__index");
    lua_rawset(L, LUA_REGISTRYINDEX);
    /* }}} */
}


void
ngx_tcp_lua_inject_req_socket_api(lua_State *L)
{
    lua_newtable(L);    /* .req */

    lua_pushcfunction(L, ngx_tcp_lua_req_socket);
    lua_setfield(L, -2, "socket");

    lua_setfield(L, -2, "req");
}


static int
ngx_tcp_lua_socket_error_retval_handler(ngx_tcp_session_t *s,
    ngx_tcp_lua_socket_upstream_t *u, lua_State *L)
{
    u_char           errstr[NGX_MAX_ERROR_STR];
    u_char          *p;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, s->connection->log, 0,
                   "lua socket error retval handler");

    ngx_tcp_lua_socket_finalize(s, u);

    if (u->ft_type & NGX_TCP_LUA_SOCKET_FT_RESOLVER) {
        return 2;
    }

    lua_pushnil(L);

    if (u->ft_type & NGX_TCP_LUA_SOCKET_FT_TIMEOUT) {
        lua_pushliteral(L, "timeout");

    } else if (u->ft_type & NGX_TCP_LUA_SOCKET_FT_CLOSED) {
        lua_pushliteral(L, "closed");

    } else if (u->ft_type & NGX_TCP_LUA_SOCKET_FT_BUFTOOSMALL) {
        lua_pushliteral(L, "buffer too small");

    } else if (u->ft_type & NGX_TCP_LUA_SOCKET_FT_NOMEM) {
        lua_pushliteral(L, "out of memory");

    } else {

        if (u->socket_errno) {
#if (nginx_version >= 1000000)
            p = ngx_strerror(u->socket_errno, errstr, sizeof(errstr));
#else
            p = ngx_strerror_r(u->socket_errno, errstr, sizeof(errstr));
#endif
            /* for compatibility with LuaSocket */
            ngx_strlow(errstr, errstr, p - errstr);
            lua_pushlstring(L, (char *) errstr, p - errstr);

        } else {
            lua_pushliteral(L, "error");
        }
    }

    return 2;
}


static int
ngx_tcp_lua_socket_tcp(lua_State *L)
{
    ngx_tcp_session_t      *s;
    ngx_tcp_lua_ctx_t      *ctx;

    if (lua_gettop(L) != 0) {
        return luaL_error(L, "expecting zero arguments, but got %d",
                lua_gettop(L));
    }

    lua_pushlightuserdata(L, &ngx_tcp_lua_request_key);
    lua_rawget(L, LUA_GLOBALSINDEX);
    s = lua_touserdata(L, -1);
    lua_pop(L, 1);

    if (s == NULL) {
        return luaL_error(L, "no request found");
    }

    ctx = ngx_tcp_get_module_ctx(s, ngx_tcp_lua_module);
    if (ctx == NULL) {
        return luaL_error(L, "no ctx found");
    }

    lua_createtable(L, 3 /* narr */, 1 /* nrec */);
    lua_pushlightuserdata(L, &ngx_tcp_lua_tcp_socket_metatable_key);
    lua_rawget(L, LUA_REGISTRYINDEX);
    lua_setmetatable(L, -2);

    dd("top: %d", lua_gettop(L));

    return 1;
}


static int
ngx_tcp_lua_socket_tcp_receive(lua_State *L)
{
    ngx_tcp_session_t                  *s;
    ngx_tcp_lua_socket_upstream_t      *u;
    ngx_int_t                            rc;
    ngx_tcp_lua_ctx_t                  *ctx;
    int                                  n;
    ngx_str_t                            pat;
    lua_Integer                          bytes;
    char                                *p;
    int                                  typ;

    n = lua_gettop(L);
    if (n != 1 && n != 2) {
        return luaL_error(L, "expecting 1 or 2 arguments "
                          "(including the object), but got %d", n);
    }

    lua_pushlightuserdata(L, &ngx_tcp_lua_request_key);
    lua_rawget(L, LUA_GLOBALSINDEX);
    s = lua_touserdata(L, -1);
    lua_pop(L, 1);

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, s->connection->log, 0,
                   "lua socket calling receive() method");

    luaL_checktype(L, 1, LUA_TTABLE);

    lua_rawgeti(L, 1, SOCKET_CTX_INDEX);
    u = lua_touserdata(L, -1);

    if (u == NULL || u->peer.connection == NULL || u->ft_type || u->eof) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "attempt to receive data on a closed socket: u:%p, c:%p, "
                      "ft:%ui eof:%ud",
                      u, u ? u->peer.connection : NULL, u ? u->ft_type : 0,
                      u ? u->eof : 0);

        lua_pushnil(L);
        lua_pushliteral(L, "closed");
        return 2;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0,
                   "lua socket read timeout: %M", u->read_timeout);

    if (n > 1) {
        if (lua_isnumber(L, 2)) {
            typ = LUA_TNUMBER;

        } else {
            typ = lua_type(L, 2);
        }

        switch (typ) {
        case LUA_TSTRING:
            pat.data = (u_char *) luaL_checklstring(L, 2, &pat.len);
            if (pat.len != 2 || pat.data[0] != '*') {
                p = (char *) lua_pushfstring(L, "bad pattern argument: %s",
                                    (char *) pat.data);

                return luaL_argerror(L, 2, p);
            }

            switch (pat.data[1]) {
            case 'l':
                u->input_filter = ngx_tcp_lua_socket_read_line;
                break;

            case 'a':
                u->input_filter = ngx_tcp_lua_socket_read_all;
                break;

            default:
                return luaL_argerror(L, 2, "bad pattern argument");
                break;
            }

            u->length = 0;
            u->rest = 0;

            break;

        case LUA_TNUMBER:
            bytes = lua_tointeger(L, 2);
            if (bytes < 0) {
                return luaL_argerror(L, 2, "bad pattern argument");
            }

            u->input_filter = ngx_tcp_lua_socket_read_chunk;
            u->length = (size_t) bytes;
            u->rest = u->length;

            break;

        default:
            return luaL_argerror(L, 2, "bad pattern argument");
            break;
        }

    } else {
        u->input_filter = ngx_tcp_lua_socket_read_line;
        u->length = 0;
        u->rest = 0;
    }

    u->input_filter_ctx = u;

    ctx = ngx_tcp_get_module_ctx(s, ngx_tcp_lua_module);

    if (u->bufs_in == NULL) {
        u->bufs_in =
            ngx_tcp_lua_chains_get_free_buf(s->connection->log, s->pool,
                                             &ctx->free_recv_bufs,
                                             u->conf->buffer_size,
                                             (ngx_buf_tag_t)
                                             &ngx_tcp_lua_module);

        if (u->bufs_in == NULL) {
            return luaL_error(L, "out of memory");
        }

        u->buf_in = u->bufs_in;
        u->buffer = *u->buf_in->buf;
    }

    dd("tcp receive: buf_in: %p, bufs_in: %p", u->buf_in, u->bufs_in);

    u->waiting = 0;

    rc = ngx_tcp_lua_socket_read(s, u);

    if (rc == NGX_ERROR) {
        dd("read failed: %d", (int) u->ft_type);
        rc = ngx_tcp_lua_socket_tcp_receive_retval_handler(s, u, L);
        dd("tcp receive retval returned: %d", (int) rc);
        return rc;
    }

    if (rc == NGX_OK) {

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, s->connection->log, 0,
                       "lua socket receive done in a single run");

        return ngx_tcp_lua_socket_tcp_receive_retval_handler(s, u, L);
    }

    /* rc == NGX_AGAIN */

    u->read_event_handler = ngx_tcp_lua_socket_read_handler;
    u->write_event_handler = ngx_tcp_lua_socket_dummy_handler;

/*
    if (ctx->entered_content_phase) {
        r->write_event_handler = ngx_tcp_lua_content_wev_handler;
    }
*/
    s->write_event_handler = ngx_tcp_lua_wev_handler;
    
    u->waiting = 1;
    u->prepare_retvals = ngx_tcp_lua_socket_tcp_receive_retval_handler;

    ctx->data = u;
    ctx->socket_busy = 1;
    ctx->socket_ready = 0;

    return lua_yield(L, 0);
}


static ngx_int_t
ngx_tcp_lua_socket_read_chunk(void *data, ssize_t bytes)
{
    ngx_tcp_lua_socket_upstream_t      *u = data;

    ngx_buf_t                   *b;
#if (NGX_DEBUG)
    ngx_tcp_session_t          *s;

    s = u->session;
#endif

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0,
                   "lua socket read chunk %z", bytes);

    if (bytes == 0) {
        u->ft_type |= NGX_TCP_LUA_SOCKET_FT_CLOSED;
        return NGX_ERROR;
    }

    b = &u->buffer;

    if (bytes >= (ssize_t) u->rest) {

        u->buf_in->buf->last += u->rest;
        b->pos += u->rest;
        u->rest = 0;

        return NGX_OK;
    }

    /* bytes < u->rest */

    u->buf_in->buf->last += bytes;
    b->pos += bytes;
    u->rest -= bytes;

    return NGX_AGAIN;
}


static ngx_int_t
ngx_tcp_lua_socket_read_all(void *data, ssize_t bytes)
{
    ngx_tcp_lua_socket_upstream_t      *u = data;

    ngx_buf_t                   *b;
#if (NGX_DEBUG)
    ngx_tcp_session_t          *s;

    s = u->session;
#endif

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, s->connection->log, 0,
                   "lua socket read all");

    if (bytes == 0) {
        return NGX_OK;
    }

    b = &u->buffer;

    u->buf_in->buf->last += bytes;
    b->pos += bytes;

    return NGX_AGAIN;
}


static ngx_int_t
ngx_tcp_lua_socket_read_line(void *data, ssize_t bytes)
{
    ngx_tcp_lua_socket_upstream_t      *u = data;

    ngx_buf_t                   *b;
    u_char                      *dst;
    u_char                       c;
#if (NGX_DEBUG)
    u_char                      *begin;
#endif

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, u->session->connection->log, 0,
                   "lua socket read line");

    if (bytes == 0) {
        u->ft_type |= NGX_TCP_LUA_SOCKET_FT_CLOSED;
        return NGX_ERROR;
    }

    b = &u->buffer;

#if (NGX_DEBUG)
    begin = b->pos;
#endif

    dd("already read: %p: %.*s", u->buf_in,
            (int) (u->buf_in->buf->last - u->buf_in->buf->pos),
            u->buf_in->buf->pos);

    dd("data read: %.*s", (int) bytes, b->pos);

    dst = u->buf_in->buf->last;

    while (bytes--) {

        c = *b->pos++;

        switch (c) {
        case '\n':
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, u->session->connection->log, 0,
                           "lua socket read the final line part: \"%*s\"",
                           b->pos - 1 - begin, begin);

            u->buf_in->buf->last = dst;

            dd("read a line: %p: %.*s", u->buf_in,
                    (int) (u->buf_in->buf->last - u->buf_in->buf->pos),
                    u->buf_in->buf->pos);

            return NGX_OK;

        case '\r':
            /* ignore it */
            break;

        default:
            *dst++ = c;
            break;
        }
    }

#if (NGX_DEBUG)
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, u->session->connection->log, 0,
                   "lua socket read partial line data: %*s",
                   dst - begin, begin);
#endif

    u->buf_in->buf->last = dst;

    return NGX_AGAIN;
}


static ngx_int_t
ngx_tcp_lua_socket_read(ngx_tcp_session_t *s,
    ngx_tcp_lua_socket_upstream_t *u)
{
    ngx_int_t                    rc;
    ngx_connection_t            *c;
    ngx_buf_t                   *b;
    ngx_event_t                 *rev;
    size_t                       size;
    ssize_t                      n;
    unsigned                     read;
    //size_t                       preread = 0;

    c = u->peer.connection;
    rev = c->read;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "lua socket read data: waiting: %d", (int) u->waiting);

    b = &u->buffer;
    read = 0;

    for ( ;; ) {

        size = b->last - b->pos;

        if (size || u->eof) {

            rc = u->input_filter(u->input_filter_ctx, size);

            if (rc == NGX_OK) {
                ngx_log_debug3(NGX_LOG_DEBUG_HTTP, s->connection->log, 0,
                               "lua socket receive done: wait:%d, eof:%d, "
                               "uri:\"%p\"", (int) u->waiting, (int) u->eof,
                               s);

                if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                    ngx_tcp_lua_socket_handle_error(s, u,
                                     NGX_TCP_LUA_SOCKET_FT_ERROR);
                    return NGX_ERROR;
                }

                ngx_tcp_lua_socket_handle_success(s, u);
                return NGX_OK;
            }

            if (rc == NGX_ERROR) {
                dd("input filter error: ft_type:%d waiting:%d",
                        (int) u->ft_type, (int) u->waiting);

                ngx_tcp_lua_socket_handle_error(s, u,
                                                 NGX_TCP_LUA_SOCKET_FT_ERROR);
                return NGX_ERROR;
            }

            /* rc == NGX_AGAIN */
/*
            if (u->is_downstream && s->request_body->rest == 0) {
                u->eof = 1;
            }
*/
            continue;
        }

        if (read && !rev->ready) {
            rc = NGX_AGAIN;
            break;
        }

        size = b->end - b->last;

        if (size == 0) {
            rc = ngx_tcp_lua_socket_add_input_buffer(s, u);
            if (rc == NGX_ERROR) {
                ngx_tcp_lua_socket_handle_error(s, u,
                                                 NGX_TCP_LUA_SOCKET_FT_NOMEM);

                return NGX_ERROR;
            }

            b = &u->buffer;
            size = b->end - b->last;
        }

#if 1
        if (rev->active && !rev->ready) {
            rc = NGX_AGAIN;
            break;
        }
#endif

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0,
                       "lua socket try to recv data %p", s);

        n = c->recv(c, b->last, size);

        dd("read event ready: %d", (int) c->read->ready);

        read = 1;

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, s->connection->log, 0,
                       "lua socket recv returned %d: \"%p\"",
                       (int) n, s);

        if (n == NGX_AGAIN) {
            rc = NGX_AGAIN;
            dd("socket recv busy");
            break;
        }

        if (n == 0) {
            u->eof = 1;

            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, s->connection->log, 0,
                           "lua socket closed");

            continue;
        }

        if (n == NGX_ERROR) {
            ngx_tcp_lua_socket_handle_error(s, u,
                                             NGX_TCP_LUA_SOCKET_FT_ERROR);
            return NGX_ERROR;
        }

        b->last += n;
/*
        if (u->is_downstream) {
            r->request_length += n;
            r->request_body->rest -= n;
        }
        */
    }

    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        ngx_tcp_lua_socket_handle_error(s, u,
                                         NGX_TCP_LUA_SOCKET_FT_ERROR);
        return NGX_ERROR;
    }

    if (rev->active) {
        ngx_add_timer(rev, u->read_timeout);

    } else if (rev->timer_set) {
        ngx_del_timer(rev);
    }

    return rc;
}


static void
ngx_tcp_lua_socket_read_handler(ngx_tcp_session_t *s,
    ngx_tcp_lua_socket_upstream_t *u)
{
    ngx_connection_t            *c;

    c = u->peer.connection;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, s->connection->log, 0,
                   "lua socket read handler");

    if (c->read->timedout) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "lua socket read timed out");

        ngx_tcp_lua_socket_handle_error(s, u, NGX_TCP_LUA_SOCKET_FT_TIMEOUT);
        return;
    }

#if 1
    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }
#endif

    if (u->buffer.start != NULL) {
        (void) ngx_tcp_lua_socket_read(s, u);
    }
}


static int
ngx_tcp_lua_socket_tcp_receive_retval_handler(ngx_tcp_session_t *s,
    ngx_tcp_lua_socket_upstream_t *u, lua_State *L)
{
    int                          n;
    ngx_int_t                    rc;
    ngx_tcp_lua_ctx_t          *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, s->connection->log, 0,
                   "lua socket receive return value handler");

    ctx = ngx_tcp_get_module_ctx(s, ngx_tcp_lua_module);

    if (u->ft_type) {

        dd("u->bufs_in: %p", u->bufs_in);

        if (u->bufs_in) {
            rc = ngx_tcp_lua_socket_push_input_data(s, ctx, u, L);
            if (rc == NGX_ERROR) {
                lua_pushnil(L);
                lua_pushliteral(L, "out of memory");
                return 2;
            }

            (void) ngx_tcp_lua_socket_error_retval_handler(s, u, L);

            lua_pushvalue(L, -3);
            lua_remove(L, -4);
            return 3;
        }

        n = ngx_tcp_lua_socket_error_retval_handler(s, u, L);
        lua_pushliteral(L, "");
        return n + 1;
    }

    rc = ngx_tcp_lua_socket_push_input_data(s, ctx, u, L);
    if (rc == NGX_ERROR) {
        lua_pushnil(L);
        lua_pushliteral(L, "out of memory");
        return 2;
    }

    return 1;
}


static void
ngx_tcp_lua_socket_handle_success(ngx_tcp_session_t *s,
    ngx_tcp_lua_socket_upstream_t *u)
{
    ngx_tcp_lua_ctx_t          *ctx;

#if 1
    u->read_event_handler = ngx_tcp_lua_socket_dummy_handler;
    u->write_event_handler = ngx_tcp_lua_socket_dummy_handler;
#endif

#if 0
    if (u->eof) {
        ngx_tcp_lua_socket_finalize(r, u);
    }
#endif

    if (u->waiting) {
        u->waiting = 0;

        ctx = ngx_tcp_get_module_ctx(s, ngx_tcp_lua_module);

        dd("setting socket_ready to 1");

        ctx->socket_busy = 0;
        ctx->socket_ready = 1;

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, s->connection->log, 0,
                       "lua socket waking up the current request");

        s->write_event_handler(s);
    }
}


static void
ngx_tcp_lua_socket_handle_error(ngx_tcp_session_t *s,
    ngx_tcp_lua_socket_upstream_t *u, ngx_uint_t ft_type)
{
    ngx_tcp_lua_ctx_t          *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, s->connection->log, 0,
                   "lua socket handle error");

    u->ft_type |= ft_type;

#if 0
    ngx_tcp_lua_socket_finalize(r, u);
#endif

    u->read_event_handler = ngx_tcp_lua_socket_dummy_handler;
    u->write_event_handler = ngx_tcp_lua_socket_dummy_handler;

    if (u->waiting) {
        u->waiting = 0;

        ctx = ngx_tcp_get_module_ctx(s, ngx_tcp_lua_module);

        dd("setting socket_ready to 1");

        ctx->socket_busy = 0;
        ctx->socket_ready = 1;

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, s->connection->log, 0,
                       "lua socket waking up the current request");

        s->write_event_handler(s);
    }
}


static void
ngx_tcp_lua_socket_finalize(ngx_tcp_session_t *r,
    ngx_tcp_lua_socket_upstream_t *u)
{
    ngx_tcp_lua_socket_pool_t          *spool;
    ngx_chain_t                         *cl;
    ngx_chain_t                        **ll;
    ngx_tcp_lua_ctx_t                  *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua finalize socket");

    ctx = ngx_tcp_get_module_ctx(r, ngx_tcp_lua_module);

    if (ctx && u->bufs_in) {

        ll = &u->bufs_in;
        for (cl = u->bufs_in; cl; cl = cl->next) {
            dd("bufs_in chain: %p, next %p", cl, cl->next);
            cl->buf->pos = cl->buf->last;
            ll = &cl->next;
        }

        dd("ctx: %p", ctx);
        dd("free recv bufs: %p", ctx->free_recv_bufs);
        *ll = ctx->free_recv_bufs;
        ctx->free_recv_bufs = u->bufs_in;
        u->bufs_in = NULL;
        u->buf_in = NULL;
        ngx_memzero(&u->buffer, sizeof(ngx_buf_t));
    }

    if (u->cleanup) {
        *u->cleanup = NULL;
        u->cleanup = NULL;
    }

    if (u->is_downstream) {
        //todo: r->read_event_handler = ngx_tcp_lua_dummy_read_handler;
        u->peer.connection = NULL;
        return;
    }
/*
    if (u->resolved && u->resolved->ctx) {
        ngx_resolve_name_done(u->resolved->ctx);
        u->resolved->ctx = NULL;
    }
*/
    if (u->peer.free) {
        u->peer.free(&u->peer, u->peer.data, 0);
    }

    if (u->peer.connection) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "lua close socket connection");

        ngx_close_connection(u->peer.connection);
        u->peer.connection = NULL;
/*
        if (!u->reused) {
            return;
        }
*/
        spool = u->socket_pool;
        if (spool == NULL) {
            return;
        }

        spool->active_connections--;

        if (spool->active_connections == 0) {
            ngx_tcp_lua_socket_free_pool(r->connection->log, spool);
        }
    }
}


static int
ngx_tcp_lua_req_socket(lua_State *L)
{
    ngx_peer_connection_t           *pc;
    ngx_tcp_lua_srv_conf_t         *lscf;
    ngx_connection_t                *c;
    ngx_tcp_session_t              *s;
    ngx_tcp_lua_socket_upstream_t  *u;
    ngx_tcp_lua_ctx_t              *ctx;
    ngx_tcp_cleanup_t              *cln;

    if (lua_gettop(L) != 0) {
        return luaL_error(L, "expecting zero arguments, but got %d",
                lua_gettop(L));
    }

    lua_pushlightuserdata(L, &ngx_tcp_lua_request_key);
    lua_rawget(L, LUA_GLOBALSINDEX);
    s = lua_touserdata(L, -1);
    lua_pop(L, 1);

    ctx = ngx_tcp_get_module_ctx(s, ngx_tcp_lua_module);
    if (ctx == NULL) {
        return luaL_error(L, "no ctx found");
    }

    lua_createtable(L, 3 /* narr */, 1 /* nrec */); /* the object */

    lua_pushlightuserdata(L, &ngx_tcp_lua_req_socket_metatable_key);
    lua_rawget(L, LUA_REGISTRYINDEX);
    lua_setmetatable(L, -2);

    u = lua_newuserdata(L, sizeof(ngx_tcp_lua_socket_upstream_t));
    if (u == NULL) {
        return luaL_error(L, "out of memory");
    }

#if 1
    lua_createtable(L, 0 /* narr */, 1 /* nrec */); /* metatable */
    lua_pushcfunction(L, ngx_tcp_lua_socket_downstream_destroy);
    lua_setfield(L, -2, "__gc");
    lua_setmetatable(L, -2);
#endif

    lua_rawseti(L, 1, SOCKET_CTX_INDEX);

    ngx_memzero(u, sizeof(ngx_tcp_lua_socket_upstream_t));

    u->is_downstream = 1;

    u->session = s;

    lscf = ngx_tcp_get_module_srv_conf(s, ngx_tcp_lua_module);

    u->conf = lscf;

    u->read_timeout = u->conf->read_timeout;
    u->connect_timeout = u->conf->connect_timeout;
    u->send_timeout = u->conf->send_timeout;

    cln = ngx_tcp_cleanup_add(s, 0);
    if (cln == NULL) {
        u->ft_type |= NGX_TCP_LUA_SOCKET_FT_ERROR;
        lua_pushnil(L);
        lua_pushliteral(L, "out of memory");
        return 2;
    }

    cln->handler = ngx_tcp_lua_req_socket_cleanup;
    cln->data = u;
    u->cleanup = &cln->handler;

    pc = &u->peer;

    pc->log = s->connection->log;
    pc->log_error = NGX_ERROR_ERR;

    c = s->connection;
    pc->connection = c;

    ctx->data = u;

    s->read_event_handler = ngx_tcp_lua_req_socket_rev_handler;

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    lua_settop(L, 1);
    lua_pushnil(L);
    return 2;
}


static void
ngx_tcp_lua_req_socket_rev_handler(ngx_tcp_session_t *s)
{
    ngx_tcp_lua_ctx_t              *ctx;
    ngx_tcp_lua_socket_upstream_t  *u;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, s->connection->log, 0,
                   "lua request socket read event handler");

    ctx = ngx_tcp_get_module_ctx(s, ngx_tcp_lua_module);
    if (ctx == NULL) {
        return;
    }

    u = ctx->data;

    if (u && u->read_event_handler) {
        u->read_event_handler(s, u);
    }
}


static int
ngx_tcp_lua_socket_downstream_destroy(lua_State *L)
{
    ngx_tcp_lua_socket_upstream_t          *u;

    dd("upstream destroy triggered by Lua GC");

    u = lua_touserdata(L, 1);
    if (u == NULL) {
        return 0;
    }

    if (u->cleanup) {
        ngx_tcp_lua_req_socket_cleanup(u); /* it will clear u->cleanup */
    }

    return 0;
}


static void
ngx_tcp_lua_req_socket_cleanup(void *data)
{
    ngx_tcp_lua_socket_upstream_t  *u = data;

#if (NGX_DEBUG)
    ngx_tcp_session_t  *s;

    s = u->session;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0,
                   "cleanup lua socket downstream request: \"%p\"", s);
#endif

    if (u->cleanup) {
        *u->cleanup = NULL;
        u->cleanup = NULL;
    }

    if (u->peer.connection) {
        u->peer.connection = NULL;
    }
}


static void
ngx_tcp_lua_socket_dummy_handler(ngx_tcp_session_t *s,
    ngx_tcp_lua_socket_upstream_t *u)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, s->connection->log, 0,
                   "lua socket dummy handler");
}


static ngx_int_t
ngx_tcp_lua_socket_add_input_buffer(ngx_tcp_session_t *s,
    ngx_tcp_lua_socket_upstream_t *u)
{
    ngx_chain_t             *cl;
    ngx_tcp_lua_ctx_t      *ctx;

    ctx = ngx_tcp_get_module_ctx(s, ngx_tcp_lua_module);

    cl = ngx_tcp_lua_chains_get_free_buf(s->connection->log, s->pool,
                                          &ctx->free_recv_bufs,
                                          u->conf->buffer_size,
                                          (ngx_buf_tag_t)
                                          &ngx_tcp_lua_module);

    if (cl == NULL) {
        return NGX_ERROR;
    }

    u->buf_in->next = cl;
    u->buf_in = cl;
    u->buffer = *cl->buf;

    return NGX_OK;
}


static ngx_int_t
ngx_tcp_lua_socket_push_input_data(ngx_tcp_session_t *s,
    ngx_tcp_lua_ctx_t *ctx, ngx_tcp_lua_socket_upstream_t *u, lua_State *L)
{
    ngx_chain_t             *cl;
    ngx_chain_t            **ll;
    size_t                   size;
    ngx_buf_t               *b;
    size_t                   nbufs;
    u_char                  *p;
    u_char                  *last;

    if (!u->bufs_in) {
        lua_pushliteral(L, "");
        return NGX_OK;
    }

    dd("bufs_in: %p, buf_in: %p", u->bufs_in, u->buf_in);

    size = 0;
    nbufs = 0;
    ll = NULL;

    for (cl = u->bufs_in; cl; cl = cl->next) {
        b = cl->buf;
        size += b->last - b->pos;

        if (cl->next) {
            ll = &cl->next;
        }

        nbufs++;
    }

    dd("size: %d, nbufs: %d", (int) size, (int) nbufs);

    if (size == 0) {
        lua_pushliteral(L, "");

        goto done;
    }

    if (nbufs == 1) {
        b = u->buf_in->buf;
        lua_pushlstring(L, (char *) b->pos, b->last - b->pos);

        dd("copying input data chunk from %p: \"%.*s\"", u->buf_in,
            (int) (b->last - b->pos), b->pos);

        goto done;
    }

    /* nbufs > 1 */

    dd("WARN: allocate a big memory: %d", (int) size);

    p = ngx_palloc(s->pool, size);
    if (p == NULL) {
        return NGX_ERROR;
    }

    last = p;
    for (cl = u->bufs_in; cl; cl = cl->next) {
        b = cl->buf;
        last = ngx_copy(last, b->pos, b->last - b->pos);

        dd("copying input data chunk from %p: \"%.*s\"", cl,
            (int) (b->last - b->pos), b->pos);
    }

    lua_pushlstring(L, (char *) p, size);

    ngx_pfree(s->pool, p);

done:
    if (nbufs > 1 && ll) {
        dd("recycle buffers: %d", (int) (nbufs - 1));

        *ll = ctx->free_recv_bufs;
        ctx->free_recv_bufs = u->bufs_in;
        u->bufs_in = u->buf_in;
    }

    if (u->buffer.pos == u->buffer.last) {
        dd("resetting u->buffer pos & last");
        u->buffer.pos = u->buffer.start;
        u->buffer.last = u->buffer.start;
    }

    u->buf_in->buf->last = u->buffer.pos;
    u->buf_in->buf->pos = u->buffer.pos;

    return NGX_OK;
}


static void
ngx_tcp_lua_socket_free_pool(ngx_log_t *log, ngx_tcp_lua_socket_pool_t *spool)
{
    lua_State                           *L;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                   "lua socket keepalive: free connection pool for \"%s\"",
                   spool->key);

    L = spool->conf->lua;

    lua_pushlightuserdata(L, &ngx_tcp_lua_socket_pool_key);
    lua_rawget(L, LUA_REGISTRYINDEX);
    lua_pushstring(L, (char *) spool->key);
    lua_pushnil(L);
    lua_rawset(L, -3);
    lua_pop(L, 1);
}

