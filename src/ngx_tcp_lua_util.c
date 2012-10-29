
#include "ngx_md5.h"
#include "ngx_tcp_lua_util.h"
#include "ngx_tcp_lua_output.h"
#include "ngx_tcp_lua_socket.h"
#include "ngx_tcp_lua_exception.h"


char ngx_tcp_lua_code_cache_key;
char ngx_tcp_lua_ctx_tables_key;
char ngx_tcp_lua_regex_cache_key;
char ngx_tcp_lua_socket_pool_key;
char ngx_tcp_lua_request_key;


/*  coroutine anchoring table key in Lua vm registry */
static char ngx_tcp_lua_coroutines_key;

#ifndef LUA_PATH_SEP
#define LUA_PATH_SEP ";"
#endif

#define AUX_MARK "\1"

void ngx_tcp_lua_create_new_global_table(lua_State *L, int narr, int nrec);
static void ngx_tcp_lua_inject_ngx_api(ngx_conf_t *cf, lua_State *L);


static void
ngx_tcp_lua_set_path(ngx_conf_t *cf, lua_State *L, int tab_idx,
        const char *fieldname, const char *path, const char *default_path)
{
    const char          *tmp_path;
    const char          *prefix;

    /* XXX here we use some hack to simplify string manipulation */
    tmp_path = luaL_gsub(L, path, LUA_PATH_SEP LUA_PATH_SEP,
            LUA_PATH_SEP AUX_MARK LUA_PATH_SEP);

    lua_pushlstring(L, (char *) cf->cycle->prefix.data, cf->cycle->prefix.len);
    prefix = lua_tostring(L, -1);
    tmp_path = luaL_gsub(L, tmp_path, "$prefix", prefix);
    tmp_path = luaL_gsub(L, tmp_path, "${prefix}", prefix);
    lua_pop(L, 3);

    tmp_path = luaL_gsub(L, tmp_path, AUX_MARK, default_path);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, cf->log, 0,
            "lua setting lua package.%s to \"%s\"", fieldname, tmp_path);

    lua_remove(L, -2);

    /* fix negative index as there's new data on stack */
    tab_idx = (tab_idx < 0) ? (tab_idx - 1) : tab_idx;
    lua_setfield(L, tab_idx, fieldname);
}


static void
ngx_tcp_lua_init_registry(ngx_conf_t *cf, lua_State *L)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->log, 0,
            "lua initializing lua registry");

    /* {{{ register a table to anchor lua coroutines reliably:
     * {([int]ref) = [cort]} */
    lua_pushlightuserdata(L, &ngx_tcp_lua_coroutines_key);
    lua_newtable(L);
    lua_rawset(L, LUA_REGISTRYINDEX);
    /* }}} */

    /* create the registry entry for the Lua request ctx data table */
    lua_pushlightuserdata(L, &ngx_tcp_lua_ctx_tables_key);
    lua_newtable(L);
    lua_rawset(L, LUA_REGISTRYINDEX);

    /* create the registry entry for the Lua socket connection pool table */
    lua_pushlightuserdata(L, &ngx_tcp_lua_socket_pool_key);
    lua_newtable(L);
    lua_rawset(L, LUA_REGISTRYINDEX);

}


static void
ngx_tcp_lua_init_globals(ngx_conf_t *cf, lua_State *L)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->log, 0,
            "lua initializing lua globals");

    /* {{{ remove unsupported globals */
    lua_pushnil(L);
    lua_setfield(L, LUA_GLOBALSINDEX, "coroutine");
    /* }}} */


    ngx_tcp_lua_inject_ngx_api(cf, L);
}


static void
ngx_tcp_lua_inject_ngx_api(ngx_conf_t *cf, lua_State *L)
{
    lua_createtable(L, 0 /* narr */, 89 /* nrec */);    /* ngx.* */

    ngx_tcp_lua_inject_output_api(L);
    
    ngx_tcp_lua_inject_req_socket_api(L);

    ngx_tcp_lua_inject_socket_api(cf->log, L);

    lua_getglobal(L, "package"); /* ngx package */
    lua_getfield(L, -1, "loaded"); /* ngx package loaded */
    lua_pushvalue(L, -3); /* ngx package loaded ngx */
    lua_setfield(L, -2, "ngx"); /* ngx package loaded */
    lua_pop(L, 2);

    lua_setglobal(L, "ngx");
}


lua_State *
ngx_tcp_lua_new_state(ngx_conf_t *cf, ngx_tcp_lua_main_conf_t *lmcf)
{
    lua_State       *L;
    const char      *old_path;
    const char      *new_path;
    size_t           old_path_len;
    const char      *old_cpath;
    const char      *new_cpath;
    size_t           old_cpath_len;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->log, 0, "lua creating new vm state");

    L = luaL_newstate();
    if (L == NULL) {
        return NULL;
    }

    luaL_openlibs(L);

    lua_getglobal(L, "package");

    if (!lua_istable(L, -1)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "the \"package\" table does not exist");
        return NULL;
    }

#ifdef LUA_DEFAULT_PATH
#   define LUA_DEFAULT_PATH_LEN (sizeof(LUA_DEFAULT_PATH) - 1)
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, cf->log, 0,
            "lua prepending default package.path with %s", LUA_DEFAULT_PATH);

    lua_pushliteral(L, LUA_DEFAULT_PATH ";"); /* package default */
    lua_getfield(L, -2, "path"); /* package default old */
    old_path = lua_tolstring(L, -1, &old_path_len);
    lua_concat(L, 2); /* package new */
    lua_setfield(L, -2, "path"); /* package */
#endif

#ifdef LUA_DEFAULT_CPATH
#   define LUA_DEFAULT_CPATH_LEN (sizeof(LUA_DEFAULT_CPATH) - 1)
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, cf->log, 0,
            "lua prepending default package.cpath with %s", LUA_DEFAULT_CPATH);

    lua_pushliteral(L, LUA_DEFAULT_CPATH ";"); /* package default */
    lua_getfield(L, -2, "cpath"); /* package default old */
    old_cpath = lua_tolstring(L, -1, &old_cpath_len);
    lua_concat(L, 2); /* package new */
    lua_setfield(L, -2, "cpath"); /* package */
#endif

    if (lmcf->lua_path.len != 0) {
        lua_getfield(L, -1, "path"); /* get original package.path */
        old_path = lua_tolstring(L, -1, &old_path_len);

        lua_pushlstring(L, (char *) lmcf->lua_path.data, lmcf->lua_path.len);
        new_path = lua_tostring(L, -1);

        ngx_tcp_lua_set_path(cf, L, -3, "path", new_path, old_path);

        lua_pop(L, 2);
    }

    if (lmcf->lua_cpath.len != 0) {
        lua_getfield(L, -1, "cpath"); /* get original package.cpath */
        old_cpath = lua_tolstring(L, -1, &old_cpath_len);

        lua_pushlstring(L, (char *) lmcf->lua_cpath.data, lmcf->lua_cpath.len);
        new_cpath = lua_tostring(L, -1);

        ngx_tcp_lua_set_path(cf, L, -3, "cpath", new_cpath, old_cpath);

        lua_pop(L, 2);
    }

    lua_remove(L, -1); /* remove the "package" table */

    ngx_tcp_lua_init_registry(cf, L);
    ngx_tcp_lua_init_globals(cf, L);

    return L;
}


lua_State *
ngx_tcp_lua_new_thread(ngx_tcp_session_t *s, lua_State *L, int *ref)
{
    int              top;
    lua_State       *cr;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, s->connection->log, 0,
            "lua creating new thread");

    top = lua_gettop(L);

    lua_pushlightuserdata(L, &ngx_tcp_lua_coroutines_key);
    lua_rawget(L, LUA_REGISTRYINDEX);

    cr = lua_newthread(L);

    if (cr) {
        /*  {{{ inherit coroutine's globals to main thread's globals table
         *  for print() function will try to find tostring() in current
         *  globals table.
         */
        /*  new globals table for coroutine */
        ngx_tcp_lua_create_new_global_table(cr, 0, 0);

        lua_createtable(cr, 0, 1);
        lua_pushvalue(cr, LUA_GLOBALSINDEX);
        lua_setfield(cr, -2, "__index");
        lua_setmetatable(cr, -2);

        lua_replace(cr, LUA_GLOBALSINDEX);
        /*  }}} */

        *ref = luaL_ref(L, -2);

        if (*ref == LUA_NOREF) {
            lua_settop(L, top);  /* restore main thread stack */
            return NULL;
        }
    }

    /*  pop coroutine reference on main thread's stack after anchoring it
     *  in registry */
    lua_pop(L, 1);

    return cr;

}


void
ngx_tcp_lua_request_cleanup(void *data)
{
    ngx_tcp_session_t          *s = data;
    ngx_tcp_lua_main_conf_t    *lmcf;
    ngx_tcp_lua_ctx_t          *ctx;
    lua_State                   *L;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, s->connection->log, 0,
            "lua request cleanup");

    ctx = ngx_tcp_get_module_ctx(s, ngx_tcp_lua_module);

    /*  force coroutine handling the request quit */
    if (ctx == NULL) {
        return;
    }

    if (ctx->cleanup) {
        //*ctx->cleanup = NULL;
        ctx->cleanup = NULL;
    }

    lmcf = ngx_tcp_get_module_main_conf(s, ngx_tcp_lua_module);

    L = lmcf->lua;

    if (ctx->ctx_ref != LUA_NOREF) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, s->connection->log, 0,
                "lua release ngx.ctx");

        lua_getfield(L, LUA_REGISTRYINDEX, NGX_LUA_REQ_CTX_REF);
        luaL_unref(L, -1, ctx->ctx_ref);
        ctx->ctx_ref = LUA_NOREF;
        lua_pop(L, 1);
    }

    if (ctx->cc_ref == LUA_NOREF) {
        return;
    }

    lua_getfield(L, LUA_REGISTRYINDEX, NGX_LUA_CORT_REF);
    lua_rawgeti(L, -1, ctx->cc_ref);

    if (lua_isthread(L, -1)) {
        /*  coroutine not finished yet, force quit */
        ngx_tcp_lua_del_thread(s, L, ctx->cc_ref, 1);
        ctx->cc_ref = LUA_NOREF;

    } else {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, s->connection->log, 0,
                "lua internal error: not a thread object for the current "
                "coroutine");

        luaL_unref(L, -2, ctx->cc_ref);
    }

    lua_pop(L, 2);
}


void
ngx_tcp_lua_del_thread(ngx_tcp_session_t *s, lua_State *L, int ref,
        int force_quit)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, s->connection->log, 0,
            "lua deleting thread");

    lua_pushlightuserdata(L, &ngx_tcp_lua_coroutines_key);
    lua_rawget(L, LUA_REGISTRYINDEX);

    /* release reference to coroutine */
    luaL_unref(L, -1, ref);
    lua_pop(L, 1);

}


ngx_int_t
ngx_tcp_lua_run_thread(lua_State *L, ngx_tcp_session_t *s,
        ngx_tcp_lua_ctx_t *ctx, int nret)
{
    int                      rv;
    int                      cc_ref;
    lua_State               *cc;
    const char              *err, *msg;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, s->connection->log, 0,
            "lua run thread");

    /* set Lua VM panic handler */
    lua_atpanic(L, ngx_tcp_lua_atpanic);

    dd("ctx = %p", ctx);

    cc = ctx->co;
    cc_ref = ctx->cc_ref;

    //rv = lua_resume(cc, 0);
    //dd("%d",rv);

    NGX_LUA_EXCEPTION_TRY {

        dd("calling lua_resume: vm %p, nret %d", cc, (int) nret);

        /*  run code */
        rv = lua_resume(cc, nret);

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0,
                "lua resume returned %d", rv);

        switch (rv) {
            case LUA_YIELD:
                /*  yielded, let event handler do the rest job */
                /*  FIXME: add io cmd dispatcher here */

                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, s->connection->log, 0,
                        "lua thread yielded");

                lua_settop(cc, 0);
                return NGX_AGAIN;

            case 0:
                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, s->connection->log, 0,
                        "lua thread ended normally");

#if 0
                ngx_tcp_lua_dump_postponed(r);
#endif

                ngx_tcp_lua_del_thread(s, L, cc_ref, 0);
                ctx->cc_ref = LUA_NOREF;

                return NGX_OK;

            case LUA_ERRRUN:
                err = "runtime error";
                break;

            case LUA_ERRSYNTAX:
                err = "syntax error";
                break;

            case LUA_ERRMEM:
                err = "memory allocation error";
                break;

            case LUA_ERRERR:
                err = "error handler error";
                break;

            default:
                err = "unknown error";
                break;
        }

        if (lua_isstring(cc, -1)) {
            dd("user custom error msg");
            msg = lua_tostring(cc, -1);

        } else {
            msg = "unknown reason";
        }

        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "lua handler aborted: %s: %s", err, msg);

        ngx_tcp_lua_del_thread(s, L, cc_ref, 0);
        ctx->cc_ref = LUA_NOREF;
        ngx_tcp_lua_request_cleanup(s);

        return NGX_ERROR;
    
    } NGX_LUA_EXCEPTION_CATCH {

        dd("nginx execution restored");

    }

    return NGX_ERROR;

}


void 
ngx_tcp_lua_wev_handler(ngx_tcp_session_t *s) 
{
    int                                 nret = 0;
    ngx_int_t                           rc;
    ngx_event_t                         *wev;
    ngx_connection_t                    *c;
    ngx_tcp_lua_ctx_t                   *ctx;
    ngx_tcp_lua_main_conf_t             *lmcf;
    ngx_tcp_lua_socket_upstream_t       *tcp;

    c = s->connection;
    wev = c->write;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, wev->log, 0,
                   "tcp lua wev handler: %d", c->fd);

    if (ngx_handle_write_event(wev, 0) != NGX_OK) {
        ngx_tcp_finalize_session(s);
    }

    ctx = ngx_tcp_get_module_ctx(s, ngx_tcp_lua_module);
    if (ctx == NULL) {
        return;
    }

    if (!ctx->socket_busy && ctx->socket_ready) {

        dd("resuming socket api");

        dd("setting socket_ready to 0");

        ctx->socket_ready = 0;

        tcp = ctx->data;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0,
                       "lua tcp socket calling prepare retvals handler %p",
                       tcp->prepare_retvals);

        nret = tcp->prepare_retvals(s, tcp, ctx->co);
        if (nret == NGX_AGAIN) {
            return;
        }

    } 

    lmcf = ngx_tcp_get_module_main_conf(s, ngx_tcp_lua_module);

    dd("about to run thread for %p ", s);

    rc = ngx_tcp_lua_run_thread(lmcf->lua, s, ctx, nret);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
            "lua run thread returned %d", rc);

    if (rc == NGX_AGAIN) {
        return;
    }

    if (rc == NGX_DONE || rc == NGX_OK) {
        ngx_tcp_finalize_session(s);
        return;
    }
/*
    dd("entered content phase: %d", (int) ctx->entered_content_phase);

    if (ctx->entered_content_phase) {
        ngx_tcp_finalize_request(r, rc);
        return NGX_DONE;
    }
*/
    return;

}


/**
 * Create new table and set _G field to itself.
 *
 * After:
 *         | new table | <- top
 *         |    ...    |
 * */
void
ngx_tcp_lua_create_new_global_table(lua_State *L, int narr, int nrec)
{
    lua_createtable(L, narr, nrec + 1);
    lua_pushvalue(L, -1);
    lua_setfield(L, -2, "_G");
}


ngx_chain_t *
ngx_tcp_lua_chains_get_free_buf(ngx_log_t *log, ngx_pool_t *p,
    ngx_chain_t **free, size_t len, ngx_buf_tag_t tag)
{
    ngx_chain_t  *cl;
    ngx_buf_t    *b;

    if (*free) {
        cl = *free;
        *free = cl->next;
        cl->next = NULL;

        b = cl->buf;
        if ((size_t) (b->end - b->start) >= len) {
            ngx_log_debug4(NGX_LOG_DEBUG_HTTP, log, 0,
                    "lua reuse free buf memory %O >= %uz, cl:%p, p:%p",
                    (off_t) (b->end - b->start), len, cl, b->start);

            b->pos = b->start;
            b->last = b->start;
            b->tag = tag;
            return cl;
        }

        ngx_log_debug4(NGX_LOG_DEBUG_HTTP, log, 0,
                       "lua reuse free buf chain, but reallocate memory "
                       "because %uz >= %O, cl:%p, p:%p", len,
                       (off_t) (b->end - b->start), cl, b->start);

        if (ngx_buf_in_memory(b) && b->start) {
            ngx_pfree(p, b->start);
        }

        if (len) {
            b->start = ngx_palloc(p, len);
            if (b->start == NULL) {
                return NULL;
            }

            b->end = b->start + len;

        } else {
            b->last = NULL;
            b->end = NULL;
        }

        dd("buf start: %p", cl->buf->start);

        b->pos = b->start;
        b->last = b->start;
        b->tag = tag;

        return cl;
    }

    cl = ngx_alloc_chain_link(p);
    if (cl == NULL) {
        return NULL;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, log, 0,
                   "lua allocate new chainlink and new buf of size %uz, cl:%p",
                   len, cl);

    cl->buf = ngx_create_temp_buf(p, len);
    if (cl->buf == NULL) {
        return NULL;
    }

    dd("buf start: %p", cl->buf->start);

    cl->buf->tag = tag;
    cl->next = NULL;

    return cl;
}


u_char *
ngx_tcp_lua_digest_hex(u_char *dest, const u_char *buf, int buf_len)
{
    ngx_md5_t                     md5;
    u_char                        md5_buf[MD5_DIGEST_LENGTH];

    ngx_md5_init(&md5);
    ngx_md5_update(&md5, buf, buf_len);
    ngx_md5_final(md5_buf, &md5);

    return ngx_hex_dump(dest, md5_buf, sizeof(md5_buf));
}


