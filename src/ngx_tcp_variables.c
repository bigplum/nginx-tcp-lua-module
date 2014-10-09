
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <nginx.h>
#include "ngx_tcp.h"
#include "ngx_tcp_variables.h"
/*
static ngx_int_t ngx_tcp_variable_unknown_header_in(ngx_tcp_session_t *s,
    ngx_tcp_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_tcp_variable_unknown_header_out(ngx_tcp_session_t *s,
    ngx_tcp_variable_value_t *v, uintptr_t data);
*/
#if (NGX_HAVE_TCP_INFO)
static ngx_int_t ngx_tcp_variable_tcpinfo(ngx_tcp_session_t *s,
    ngx_tcp_variable_value_t *v, uintptr_t data);
#endif

static ngx_int_t ngx_tcp_variable_binary_remote_addr(ngx_tcp_session_t *s,
		ngx_tcp_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_tcp_variable_remote_addr(ngx_tcp_session_t *s,
    ngx_tcp_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_tcp_variable_remote_port(ngx_tcp_session_t *s,
    ngx_tcp_variable_value_t *v, uintptr_t data);


static ngx_int_t ngx_tcp_variable_nginx_version(ngx_tcp_session_t *s,
    ngx_tcp_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_tcp_variable_hostname(ngx_tcp_session_t *s,
    ngx_tcp_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_tcp_variable_pid(ngx_tcp_session_t *s,
    ngx_tcp_variable_value_t *v, uintptr_t data);

/*
 * TODO:
 *     Apache CGI: AUTH_TYPE, PATH_INFO (null), PATH_TRANSLATED
 *                 REMOTE_HOST (null), REMOTE_IDENT (null),
 *                 SERVER_SOFTWARE
 *
 *     Apache SSI: DOCUMENT_NAME, LAST_MODIFIED, USER_NAME (file owner)
 */

/*
 * the $tcp_host, $tcp_user_agent, $tcp_referer, $tcp_via,
 * and $tcp_x_forwarded_for variables may be handled by generic
 * ngx_tcp_variable_unknown_header_in(), but for performance reasons
 * they are handled using dedicated entries
 */

static ngx_tcp_variable_t  ngx_tcp_core_variables[] = {

    { ngx_string("binary_remote_addr"), NULL,
      ngx_tcp_variable_binary_remote_addr, 0, 0, 0 },

    { ngx_string("remote_addr"), NULL, ngx_tcp_variable_remote_addr, 0, 0, 0 },

    { ngx_string("remote_port"), NULL, ngx_tcp_variable_remote_port, 0, 0, 0 },

    { ngx_string("nginx_version"), NULL, ngx_tcp_variable_nginx_version,
      0, 0, 0 },

    { ngx_string("hostname"), NULL, ngx_tcp_variable_hostname,
      0, 0, 0 },

    { ngx_string("pid"), NULL, ngx_tcp_variable_pid,
      0, 0, 0 },

#if (NGX_HAVE_TCP_INFO)
    { ngx_string("tcpinfo_rtt"), NULL, ngx_tcp_variable_tcpinfo,
      0, NGX_TCP_VAR_NOCACHEABLE, 0 },

    { ngx_string("tcpinfo_rttvar"), NULL, ngx_tcp_variable_tcpinfo,
      1, NGX_TCP_VAR_NOCACHEABLE, 0 },

    { ngx_string("tcpinfo_snd_cwnd"), NULL, ngx_tcp_variable_tcpinfo,
      2, NGX_TCP_VAR_NOCACHEABLE, 0 },

    { ngx_string("tcpinfo_rcv_space"), NULL, ngx_tcp_variable_tcpinfo,
      3, NGX_TCP_VAR_NOCACHEABLE, 0 },
#endif

    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};


ngx_tcp_variable_value_t  ngx_tcp_variable_null_value =
    ngx_tcp_variable("");
ngx_tcp_variable_value_t  ngx_tcp_variable_true_value =
    ngx_tcp_variable("1");


ngx_tcp_variable_t *
ngx_tcp_add_variable(ngx_conf_t *cf, ngx_str_t *name, ngx_uint_t flags)
{
    ngx_int_t                   rc;
    ngx_uint_t                  i;
    ngx_hash_key_t             *key;
    ngx_tcp_variable_t        *v;
    ngx_tcp_core_main_conf_t  *cmcf;

    cmcf = ngx_tcp_conf_get_module_main_conf(cf, ngx_tcp_core_module);

    key = cmcf->variables_keys->keys.elts;
    for (i = 0; i < cmcf->variables_keys->keys.nelts; i++) {
        if (name->len != key[i].key.len
            || ngx_strncasecmp(name->data, key[i].key.data, name->len) != 0)
        {
            continue;
        }

        v = key[i].value;

        if (!(v->flags & NGX_TCP_VAR_CHANGEABLE)) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "the duplicate \"%V\" variable", name);
            return NULL;
        }

        return v;
    }

    v = ngx_palloc(cf->pool, sizeof(ngx_tcp_variable_t));
    if (v == NULL) {
        return NULL;
    }

    v->name.len = name->len;
    v->name.data = ngx_pnalloc(cf->pool, name->len);
    if (v->name.data == NULL) {
        return NULL;
    }

    ngx_strlow(v->name.data, name->data, name->len);

    v->set_handler = NULL;
    v->get_handler = NULL;
    v->data = 0;
    v->flags = flags;
    v->index = 0;

    rc = ngx_hash_add_key(cmcf->variables_keys, &v->name, v, 0);

    if (rc == NGX_ERROR) {
        return NULL;
    }

    if (rc == NGX_BUSY) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "conflicting variable name \"%V\"", name);
        return NULL;
    }

    return v;
}


ngx_int_t
ngx_tcp_get_variable_index(ngx_conf_t *cf, ngx_str_t *name)
{
    ngx_uint_t                  i;
    ngx_tcp_variable_t        *v;
    ngx_tcp_core_main_conf_t  *cmcf;

    cmcf = ngx_tcp_conf_get_module_main_conf(cf, ngx_tcp_core_module);

    v = cmcf->variables.elts;

    if (v == NULL) {
        if (ngx_array_init(&cmcf->variables, cf->pool, 4,
                           sizeof(ngx_tcp_variable_t))
            != NGX_OK)
        {
            return NGX_ERROR;
        }

    } else {
        for (i = 0; i < cmcf->variables.nelts; i++) {
            if (name->len != v[i].name.len
                || ngx_strncasecmp(name->data, v[i].name.data, name->len) != 0)
            {
                continue;
            }

            return i;
        }
    }

    v = ngx_array_push(&cmcf->variables);
    if (v == NULL) {
        return NGX_ERROR;
    }

    v->name.len = name->len;
    v->name.data = ngx_pnalloc(cf->pool, name->len);
    if (v->name.data == NULL) {
        return NGX_ERROR;
    }

    ngx_strlow(v->name.data, name->data, name->len);

    v->set_handler = NULL;
    v->get_handler = NULL;
    v->data = 0;
    v->flags = 0;
    v->index = cmcf->variables.nelts - 1;

    return v->index;
}


/*ngx_tcp_variable_value_t *
ngx_tcp_get_indexed_variable(ngx_tcp_session_t *s, ngx_uint_t index)
{
    ngx_tcp_variable_t        *v;
    ngx_tcp_core_main_conf_t  *cmcf;

    cmcf = ngx_tcp_get_module_main_conf(s, ngx_tcp_core_module);

    if (cmcf->variables.nelts <= index) {
        ngx_log_error(NGX_LOG_ALERT, s->connection->log, 0,
                      "unknown variable index: %d", index);
        return NULL;
    }

    if (s->variables[index].not_found || s->variables[index].valid) {
        return &s->variables[index];
    }

    v = cmcf->variables.elts;

    if (v[index].get_handler(r, &s->variables[index], v[index].data)
        == NGX_OK)
    {
        if (v[index].flags & NGX_TCP_VAR_NOCACHEABLE) {
            s->variables[index].no_cacheable = 1;
        }

        return &s->variables[index];
    }

    s->variables[index].valid = 0;
    s->variables[index].not_found = 1;

    return NULL;
}*/


/*ngx_tcp_variable_value_t *
ngx_tcp_get_flushed_variable(ngx_tcp_session_t *s, ngx_uint_t index)
{
    ngx_tcp_variable_value_t  *v;

    v = &s->variables[index];

    if (v->valid || v->not_found) {
        if (!v->no_cacheable) {
            return v;
        }

        v->valid = 0;
        v->not_found = 0;
    }

    return ngx_tcp_get_indexed_variable(r, index);
}*/


ngx_tcp_variable_value_t *
ngx_tcp_get_variable(ngx_tcp_session_t *s, ngx_str_t *name, ngx_uint_t key)
{
    ngx_tcp_variable_t        *v;
    ngx_tcp_variable_value_t  *vv;
    ngx_tcp_core_main_conf_t  *cmcf;

    cmcf = ngx_tcp_get_module_main_conf(s, ngx_tcp_core_module);

    v = ngx_hash_find(&cmcf->variables_hash, key, name->data, name->len);

    if (v) {
        if (v->flags & NGX_TCP_VAR_INDEXED) {
            return NULL;//ngx_tcp_get_flushed_variable(r, v->index);

        } else {

            vv = ngx_palloc(s->pool, sizeof(ngx_tcp_variable_value_t));

            if (vv && v->get_handler(s, vv, v->data) == NGX_OK) {
                return vv;
            }

            return NULL;
        }
    }

    vv = ngx_palloc(s->pool, sizeof(ngx_tcp_variable_value_t));
    if (vv == NULL) {
        return NULL;
    }

    /*if (ngx_strncmp(name->data, "tcp_", 5) == 0) {

        if (ngx_tcp_variable_unknown_header_in(r, vv, (uintptr_t) name)
            == NGX_OK)
        {
            return vv;
        }

        return NULL;
    }

    if (ngx_strncmp(name->data, "sent_tcp_", 10) == 0) {

        if (ngx_tcp_variable_unknown_header_out(r, vv, (uintptr_t) name)
            == NGX_OK)
        {
            return vv;
        }

        return NULL;
    }

    if (ngx_strncmp(name->data, "upstream_tcp_", 14) == 0) {

        if (ngx_tcp_upstream_header_variable(r, vv, (uintptr_t) name)
            == NGX_OK)
        {
            return vv;
        }

        return NULL;
    }*/


    vv->not_found = 1;

    return vv;
}














#if 0
static ngx_int_t
ngx_tcp_variable_unknown_header_in(ngx_tcp_session_t *s,
    ngx_tcp_variable_value_t *v, uintptr_t data)
{
    return ngx_tcp_variable_unknown_header(v, (ngx_str_t *) data,
                                            &s->headers_in.headers.part,
                                            sizeof("tcp_") - 1);
}


static ngx_int_t
ngx_tcp_variable_unknown_header_out(ngx_tcp_session_t *s,
    ngx_tcp_variable_value_t *v, uintptr_t data)
{
    return ngx_tcp_variable_unknown_header(v, (ngx_str_t *) data,
                                            &s->headers_out.headers.part,
                                            sizeof("sent_tcp_") - 1);
}


ngx_int_t
ngx_tcp_variable_unknown_header(ngx_tcp_variable_value_t *v, ngx_str_t *var,
    ngx_list_part_t *part, size_t prefix)
{
    u_char            ch;
    ngx_uint_t        i, n;
    ngx_table_elt_t  *header;

    header = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        if (header[i].hash == 0) {
            continue;
        }

        for (n = 0; n + prefix < var->len && n < header[i].key.len; n++) {
            ch = header[i].key.data[n];

            if (ch >= 'A' && ch <= 'Z') {
                ch |= 0x20;

            } else if (ch == '-') {
                ch = '_';
            }

            if (var->data[n + prefix] != ch) {
                break;
            }
        }

        if (n + prefix == var->len && n == header[i].key.len) {
            v->len = header[i].value.len;
            v->valid = 1;
            v->no_cacheable = 0;
            v->not_found = 0;
            v->data = header[i].value.data;

            return NGX_OK;
        }
    }

    v->not_found = 1;

    return NGX_OK;
}
#endif





#if (NGX_HAVE_TCP_INFO)

static ngx_int_t
ngx_tcp_variable_tcpinfo(ngx_tcp_session_t *s, ngx_tcp_variable_value_t *v,
    uintptr_t data)
{
    struct tcp_info  ti;
    socklen_t        len;
    uint32_t         value;

    len = sizeof(struct tcp_info);
    if (getsockopt(s->connection->fd, IPPROTO_TCP, TCP_INFO, &ti, &len) == -1) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = ngx_pnalloc(s->pool, NGX_INT32_LEN);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    switch (data) {
    case 0:
        value = ti.tcpi_rtt;
        break;

    case 1:
        value = ti.tcpi_rttvar;
        break;

    case 2:
        value = ti.tcpi_snd_cwnd;
        break;

    case 3:
        value = ti.tcpi_rcv_space;
        break;

    /* suppress warning */
    default:
        value = 0;
        break;
    }

    v->len = ngx_sprintf(v->data, "%uD", value) - v->data;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}

#endif



static ngx_int_t
ngx_tcp_variable_binary_remote_addr(ngx_tcp_session_t *s,
    ngx_tcp_variable_value_t *v, uintptr_t data)
{
    struct sockaddr_in   *sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6  *sin6;
#endif

    switch (s->connection->sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) s->connection->sockaddr;

        v->len = sizeof(struct in6_addr);
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = sin6->sin6_addr.s6_addr;

        break;
#endif

    default: /* AF_INET */
        sin = (struct sockaddr_in *) s->connection->sockaddr;

        v->len = sizeof(in_addr_t);
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = (u_char *) &sin->sin_addr;

        break;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_tcp_variable_remote_addr(ngx_tcp_session_t *s,
    ngx_tcp_variable_value_t *v, uintptr_t data)
{
    v->len = s->connection->addr_text.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = s->connection->addr_text.data;

    return NGX_OK;
}


static ngx_int_t
ngx_tcp_variable_remote_port(ngx_tcp_session_t *s,
    ngx_tcp_variable_value_t *v, uintptr_t data)
{
    ngx_uint_t            port;
    struct sockaddr_in   *sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6  *sin6;
#endif

    v->len = 0;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    v->data = ngx_pnalloc(s->pool, sizeof("65535") - 1);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    switch (s->connection->sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) s->connection->sockaddr;
        port = ntohs(sin6->sin6_port);
        break;
#endif

    default: /* AF_INET */
        sin = (struct sockaddr_in *) s->connection->sockaddr;
        port = ntohs(sin->sin_port);
        break;
    }

    if (port > 0 && port < 65536) {
        v->len = ngx_sprintf(v->data, "%ui", port) - v->data;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_tcp_variable_nginx_version(ngx_tcp_session_t *s,
    ngx_tcp_variable_value_t *v, uintptr_t data)
{
    v->len = sizeof(NGINX_VERSION) - 1;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = (u_char *) NGINX_VERSION;

    return NGX_OK;
}


static ngx_int_t
ngx_tcp_variable_hostname(ngx_tcp_session_t *s,
    ngx_tcp_variable_value_t *v, uintptr_t data)
{
    v->len = ngx_cycle->hostname.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = ngx_cycle->hostname.data;

    return NGX_OK;
}


static ngx_int_t
ngx_tcp_variable_pid(ngx_tcp_session_t *s,
    ngx_tcp_variable_value_t *v, uintptr_t data)
{
    u_char  *p;

    p = ngx_pnalloc(s->pool, NGX_INT64_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%P", ngx_pid) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return NGX_OK;
}

#if 0
void *
ngx_tcp_map_find(ngx_tcp_session_t *s, ngx_tcp_map_t *map, ngx_str_t *match)
{
    void        *value;
    u_char      *low;
    size_t       len;
    ngx_uint_t   key;

    len = match->len;

    if (len) {
        low = ngx_pnalloc(s->pool, len);
        if (low == NULL) {
            return NULL;
        }

    } else {
        low = NULL;
    }

    key = ngx_hash_strlow(low, match->data, len);

    value = ngx_hash_find_combined(&map->hash, key, low, len);
    if (value) {
        return value;
    }

#if (NGX_PCRE)

    if (len && map->nregex) {
        ngx_int_t              n;
        ngx_uint_t             i;
        ngx_tcp_map_regex_t  *reg;

        reg = map->regex;

        for (i = 0; i < map->nregex; i++) {

            n = ngx_tcp_regex_exec(r, reg[i].regex, match);

            if (n == NGX_OK) {
                return reg[i].value;
            }

            if (n == NGX_DECLINED) {
                continue;
            }

            /* NGX_ERROR */

            return NULL;
        }
    }

#endif

    return NULL;
}
#endif

#if 0
#if (NGX_PCRE)

static ngx_int_t
ngx_tcp_variable_not_found(ngx_tcp_session_t *s, ngx_tcp_variable_value_t *v,
    uintptr_t data)
{
    v->not_found = 1;
    return NGX_OK;
}


ngx_tcp_regex_t *
ngx_tcp_regex_compile(ngx_conf_t *cf, ngx_regex_compile_t *rc)
{
    u_char                     *p;
    size_t                      size;
    ngx_str_t                   name;
    ngx_uint_t                  i, n;
    ngx_tcp_variable_t        *v;
    ngx_tcp_regex_t           *re;
    ngx_tcp_regex_variable_t  *rv;
    ngx_tcp_core_main_conf_t  *cmcf;

    rc->pool = cf->pool;

    if (ngx_regex_compile(rc) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%V", &rc->err);
        return NULL;
    }

    re = ngx_pcalloc(cf->pool, sizeof(ngx_tcp_regex_t));
    if (re == NULL) {
        return NULL;
    }

    re->regex = rc->regex;
    re->ncaptures = rc->captures;

    cmcf = ngx_tcp_conf_get_module_main_conf(cf, ngx_tcp_core_module);
    cmcf->ncaptures = ngx_max(cmcf->ncaptures, re->ncaptures);

    n = (ngx_uint_t) rc->named_captures;

    if (n == 0) {
        return re;
    }

    rv = ngx_palloc(rc->pool, n * sizeof(ngx_tcp_regex_variable_t));
    if (rv == NULL) {
        return NULL;
    }

    re->variables = rv;
    re->nvariables = n;
    re->name = rc->pattern;

    size = rc->name_size;
    p = rc->names;

    for (i = 0; i < n; i++) {
        rv[i].capture = 2 * ((p[0] << 8) + p[1]);

        name.data = &p[2];
        name.len = ngx_strlen(name.data);

        v = ngx_tcp_add_variable(cf, &name, NGX_TCP_VAR_CHANGEABLE);
        if (v == NULL) {
            return NULL;
        }

        rv[i].index = ngx_tcp_get_variable_index(cf, &name);
        if (rv[i].index == NGX_ERROR) {
            return NULL;
        }

        v->get_handler = ngx_tcp_variable_not_found;

        p += size;
    }

    return re;
}


ngx_int_t
ngx_tcp_regex_exec(ngx_tcp_session_t *s, ngx_tcp_regex_t *re, ngx_str_t *s)
{
    ngx_int_t                   rc, index;
    ngx_uint_t                  i, n, len;
    ngx_tcp_variable_value_t  *vv;
    ngx_tcp_core_main_conf_t  *cmcf;

    cmcf = ngx_tcp_get_module_main_conf(s, ngx_tcp_core_module);

    if (re->ncaptures) {
        len = cmcf->ncaptures;

        if (r->captures == NULL) {
            r->captures = ngx_palloc(r->pool, len * sizeof(int));
            if (r->captures == NULL) {
                return NGX_ERROR;
            }
        }

    } else {
        len = 0;
    }

    rc = ngx_regex_exec(re->regex, s, r->captures, len);

    if (rc == NGX_REGEX_NO_MATCHED) {
        return NGX_DECLINED;
    }

    if (rc < 0) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      ngx_regex_exec_n " failed: %i on \"%V\" using \"%V\"",
                      rc, s, &re->name);
        return NGX_ERROR;
    }

    for (i = 0; i < re->nvariables; i++) {

        n = re->variables[i].capture;
        index = re->variables[i].index;
        vv = &r->variables[index];

        vv->len = r->captures[n + 1] - r->captures[n];
        vv->valid = 1;
        vv->no_cacheable = 0;
        vv->not_found = 0;
        vv->data = &s->data[r->captures[n]];

#if (NGX_DEBUG)
        {
        ngx_tcp_variable_t  *v;

        v = cmcf->variables.elts;

        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "tcp regex set $%V to \"%*s\"",
                       &v[index].name, vv->len, vv->data);
        }
#endif
    }

    r->ncaptures = rc * 2;
    r->captures_data = s->data;

    return NGX_OK;
}

#endif




#endif

ngx_int_t
ngx_tcp_variables_add_core_vars(ngx_conf_t *cf)
{
    ngx_int_t                   rc;
    ngx_tcp_variable_t        *cv, *v;
    ngx_tcp_core_main_conf_t  *cmcf;

    cmcf = ngx_tcp_conf_get_module_main_conf(cf, ngx_tcp_core_module);

    cmcf->variables_keys = ngx_pcalloc(cf->temp_pool,
                                       sizeof(ngx_hash_keys_arrays_t));
    if (cmcf->variables_keys == NULL) {
        return NGX_ERROR;
    }

    cmcf->variables_keys->pool = cf->pool;
    cmcf->variables_keys->temp_pool = cf->pool;

    if (ngx_hash_keys_array_init(cmcf->variables_keys, NGX_HASH_SMALL)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    for (cv = ngx_tcp_core_variables; cv->name.len; cv++) {
        v = ngx_palloc(cf->pool, sizeof(ngx_tcp_variable_t));
        if (v == NULL) {
            return NGX_ERROR;
        }

        *v = *cv;

        rc = ngx_hash_add_key(cmcf->variables_keys, &v->name, v,
                              NGX_HASH_READONLY_KEY);

        if (rc == NGX_OK) {
            continue;
        }

        if (rc == NGX_BUSY) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "conflicting variable name \"%V\"", &v->name);
        }

        return NGX_ERROR;
    }

    return NGX_OK;
}
ngx_int_t
ngx_tcp_variables_init_vars(ngx_conf_t *cf)
{
    ngx_uint_t                  i, n;
    ngx_hash_key_t             *key;
    ngx_hash_init_t             hash;
    ngx_tcp_variable_t        *v, *av;
    ngx_tcp_core_main_conf_t  *cmcf;

    /* set the handlers for the indexed tcp variables */

    cmcf = ngx_tcp_conf_get_module_main_conf(cf, ngx_tcp_core_module);

    v = cmcf->variables.elts;
    key = cmcf->variables_keys->keys.elts;

    for (i = 0; i < cmcf->variables.nelts; i++) {

        for (n = 0; n < cmcf->variables_keys->keys.nelts; n++) {

            av = key[n].value;

            if (av->get_handler
                && v[i].name.len == key[n].key.len
                && ngx_strncmp(v[i].name.data, key[n].key.data, v[i].name.len)
                   == 0)
            {
                v[i].get_handler = av->get_handler;
                v[i].data = av->data;

                av->flags |= NGX_TCP_VAR_INDEXED;
                v[i].flags = av->flags;

                av->index = i;

                goto next;
            }
        }

        /*if (ngx_strncmp(v[i].name.data, "tcp_", 5) == 0) {
            v[i].get_handler = ngx_tcp_variable_unknown_header_in;
            v[i].data = (uintptr_t) &v[i].name;

            continue;
        }

        if (ngx_strncmp(v[i].name.data, "sent_tcp_", 10) == 0) {
            v[i].get_handler = ngx_tcp_variable_unknown_header_out;
            v[i].data = (uintptr_t) &v[i].name;

            continue;
        }

        if (ngx_strncmp(v[i].name.data, "upstream_tcp_", 14) == 0) {
            v[i].get_handler = ngx_tcp_upstream_header_variable;
            v[i].data = (uintptr_t) &v[i].name;
            v[i].flags = NGX_TCP_VAR_NOCACHEABLE;

            continue;
        }*/

        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                      "unknown \"%V\" variable", &v[i].name);

        return NGX_ERROR;

    next:
        continue;
    }


    for (n = 0; n < cmcf->variables_keys->keys.nelts; n++) {
        av = key[n].value;

        if (av->flags & NGX_TCP_VAR_NOHASH) {
            key[n].key.data = NULL;
        }
    }


    hash.hash = &cmcf->variables_hash;
    hash.key = ngx_hash_key;
    hash.max_size = cmcf->variables_hash_max_size;
    hash.bucket_size = cmcf->variables_hash_bucket_size;
    hash.name = "variables_hash";
    hash.pool = cf->pool;
    hash.temp_pool = NULL;

    if (ngx_hash_init(&hash, cmcf->variables_keys->keys.elts,
                      cmcf->variables_keys->keys.nelts)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    cmcf->variables_keys = NULL;

    return NGX_OK;
}
