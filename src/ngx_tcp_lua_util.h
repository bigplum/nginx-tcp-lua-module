#ifndef NGX_TCP_LUA_UTIL_H
#define NGX_TCP_LUA_UTIL_H


#include "ngx_tcp_lua_common.h"


/* char whose address we'll use as key in Lua vm registry for
 * user code cache table */
extern char ngx_tcp_lua_code_cache_key;

/* char whose address we'll use as key in Lua vm registry for
 * all the "ngx.ctx" tables */
extern char ngx_tcp_lua_ctx_tables_key;

/* char whose address we'll use as key in Lua vm registry for
 * regex cache table  */
extern char ngx_tcp_lua_regex_cache_key;

/* char whose address we'll use as key in Lua vm registry for
 * socket connection pool table */
extern char ngx_tcp_lua_socket_pool_key;

/* char whose address we'll use as key for the nginx request pointer */
extern char ngx_tcp_lua_request_key;

/* char whose address we'll use as key for the nginx config logger */
extern char ngx_tcp_lua_cf_log_key;


/* char whose address we'll use as key for the nginx request socket pointer */
extern char ngx_tcp_lua_request_socket_key;

ngx_int_t ngx_tcp_lua_send(ngx_tcp_session_t *s,size_t *len);
lua_State *ngx_tcp_lua_new_state(ngx_conf_t *cf, ngx_tcp_lua_main_conf_t *lmcf);
lua_State *ngx_tcp_lua_new_thread(ngx_tcp_session_t *s, lua_State *L, int *ref);
void ngx_tcp_lua_request_cleanup(void *data);
void ngx_tcp_lua_del_thread(ngx_tcp_session_t *r, lua_State *L, int ref,
        int force_quit);
ngx_int_t ngx_tcp_lua_run_thread(lua_State *L, ngx_tcp_session_t *s,
        ngx_tcp_lua_ctx_t *ctx, int nret);
void ngx_tcp_lua_wev_handler(ngx_tcp_session_t *s);
ngx_chain_t *ngx_tcp_lua_chains_get_free_buf(ngx_log_t *log, ngx_pool_t *p,
    ngx_chain_t **free, size_t len, ngx_buf_tag_t tag);
u_char *ngx_tcp_lua_digest_hex(u_char *dest, const u_char *buf, int buf_len);

#endif
