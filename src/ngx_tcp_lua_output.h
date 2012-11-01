#ifndef NGX_TCP_LUA_OUTPUT_H
#define NGX_TCP_LUA_OUTPUT_H

#include "ngx_tcp_lua_common.h"

void ngx_tcp_lua_inject_output_api(lua_State *L);
size_t ngx_tcp_lua_calc_strlen_in_table(lua_State *L, int arg_i, unsigned strict);
u_char *ngx_tcp_lua_copy_str_in_table(lua_State *L, u_char *dst);


#endif 
