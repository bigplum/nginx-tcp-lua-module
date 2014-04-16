
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_TCP_VARIABLES_H_INCLUDED_
#define _NGX_TCP_VARIABLES_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_tcp.h"


typedef ngx_variable_value_t  ngx_tcp_variable_value_t;

#define ngx_tcp_variable(v)     { sizeof(v) - 1, 1, 0, 0, 0, (u_char *) v }

typedef struct ngx_tcp_variable_s  ngx_tcp_variable_t;

typedef void (*ngx_tcp_set_variable_pt) (ngx_tcp_session_t *s,
    ngx_tcp_variable_value_t *v, uintptr_t data);
typedef ngx_int_t (*ngx_tcp_get_variable_pt) (ngx_tcp_session_t *s,
    ngx_tcp_variable_value_t *v, uintptr_t data);


#define NGX_TCP_VAR_CHANGEABLE   1
#define NGX_TCP_VAR_NOCACHEABLE  2
#define NGX_TCP_VAR_INDEXED      4
#define NGX_TCP_VAR_NOHASH       8


struct ngx_tcp_variable_s {
    ngx_str_t                     name;   /* must be first to build the hash */
    ngx_tcp_set_variable_pt      set_handler;
    ngx_tcp_get_variable_pt      get_handler;
    uintptr_t                     data;
    ngx_uint_t                    flags;
    ngx_uint_t                    index;
};


ngx_tcp_variable_t *ngx_tcp_add_variable(ngx_conf_t *cf, ngx_str_t *name,
    ngx_uint_t flags);

ngx_int_t ngx_tcp_get_variable_index(ngx_conf_t *cf, ngx_str_t *name);

ngx_tcp_variable_value_t *ngx_tcp_get_indexed_variable(ngx_tcp_session_t *s,
    ngx_uint_t index);

ngx_tcp_variable_value_t *ngx_tcp_get_flushed_variable(ngx_tcp_session_t *s,
    ngx_uint_t index);


ngx_tcp_variable_value_t *ngx_tcp_get_variable(ngx_tcp_session_t *s,
    ngx_str_t *name, ngx_uint_t key);

/*ngx_int_t ngx_tcp_variable_unknown_header(ngx_tcp_variable_value_t *v,
    ngx_str_t *var, ngx_list_part_t *part, size_t prefix);*/


#define ngx_tcp_clear_variable(r, index) r->variables0[index].text.data = NULL;

#if 0
#if (NGX_PCRE)

typedef struct {
    ngx_uint_t                    capture;
    ngx_int_t                     index;
} ngx_tcp_regex_variable_t;


typedef struct {
    ngx_regex_t                  *regex;
    ngx_uint_t                    ncaptures;
    ngx_tcp_regex_variable_t    *variables;
    ngx_uint_t                    nvariables;
    ngx_str_t                     name;
} ngx_tcp_regex_t;


typedef struct {
    ngx_tcp_regex_t             *regex;
    void                         *value;
} ngx_tcp_map_regex_t;


ngx_tcp_regex_t *ngx_tcp_regex_compile(ngx_conf_t *cf,
    ngx_regex_compile_t *rc);
ngx_int_t ngx_tcp_regex_exec(ngx_tcp_session_t *s, ngx_tcp_regex_t *re,
    ngx_str_t *s);

#endif


typedef struct {
    ngx_hash_combined_t           hash;
#if (NGX_PCRE)
    ngx_tcp_map_regex_t         *regex;
    ngx_uint_t                    nregex;
#endif
} ngx_tcp_map_t;


void *ngx_tcp_map_find(ngx_tcp_session_t *s, ngx_tcp_map_t *map,
    ngx_str_t *match);





#endif
extern ngx_tcp_variable_value_t  ngx_tcp_variable_null_value;
extern ngx_tcp_variable_value_t  ngx_tcp_variable_true_value;

ngx_int_t ngx_tcp_variables_add_core_vars(ngx_conf_t *cf);
ngx_int_t ngx_tcp_variables_init_vars(ngx_conf_t *cf);
#endif /* _NGX_HTTP_VARIABLES_H_INCLUDED_ */
