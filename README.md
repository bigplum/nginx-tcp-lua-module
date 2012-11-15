nginx tcp lua module
=============
A tcp module with lua support for nginx.

Most code are copied from ngx-lua-module, and the directives/constants/APIs are 
planed to be compatible with ngx-lua module. 

Thanks for great job of ngx-lua module.

Directives
============

server

listen

so_keepalive

tcp_nodelay

timeout

resolver

resolver_timeout

allow

deny

access_log

directio_alignment

client_body_buffer_size

lua_code_cache

lua_package_path

lua_package_cpath

process_by_lua

process_by_lua_file

lua_socket_keepalive_timeout

lua_socket_connect_timeout

lua_socket_send_timeout

lua_socket_send_lowat

lua_socket_buffer_size

lua_socket_pool_size

lua_socket_read_timeout


Nginx API for Lua
============

Core constants
------------

    ngx.OK (0)
    ngx.ERROR (-1)
    ngx.AGAIN (-2)
    ngx.DONE (-4)
    ngx.DECLINED (-5)

    ngx.null


ngx.socket.tcp
------------

    connect
    send
    receive
    close
    settimeout
    setoption
    receiveuntil
    setkeepalive
    getreusedtimes

ngx.req.socket
------------

    receive
    receiveuntil

ngx.say/ngx.print
------------

ngx.log

Nginx log level constants
------------

    ngx.STDERR
    ngx.EMERG
    ngx.ALERT
    ngx.CRIT
    ngx.ERR
    ngx.WARN
    ngx.NOTICE
    ngx.INFO
    ngx.DEBUG

Installation
============

    wget http://luajit.org/download/LuaJIT-2.0.0.tar.gz
    tar -xvfz LuaJIT-2.0.0.tar.gz
    cd LuaJIT-2.0.0
    make install

    wget 'http://nginx.org/download/nginx-1.0.15.tar.gz'
    tar -xzvf nginx-1.0.15.tar.gz
    cd nginx-1.0.15/

    # tell nginx's build system where to find luajit:
    export LUAJIT_LIB=/usr/local/lib
    export LUAJIT_INC=/usr/local/include/luajit-2.0

    # or tell where to find Lua
    #export LUA_LIB=/path/to/lua/lib
    #export LUA_INC=/path/to/lua/include

    # Here we assume Nginx is to be installed under /opt/nginx/.
    ./configure --prefix=/opt/nginx \
            --add-module=/path/to/ngx-tcp-lua-module

    make -j2
    make install

    # on 64bit os, the soft link maybe needed to run nginx:

    ln -s /usr/local/lib/libluajit-5.1.so.2.0.0 /lib64/libluajit-5.1.so.2

Example
============

nginx.conf:

    tcp {
        server {
            listen 8000;
            process_by_lua_file conf/test.lua;
        }
    }

test.lua:

    local a = 0
    a = a + 1

    local f = io.open("/tmp/aaaa", "wb")
    f:write("xxxx")
    f:close()

    local sock = ngx.req.socket()

    while true do
        local re = sock:receive(10)
        if re == nil then
            break
        end
        ngx.print(re)
    end

------------

Also there is a redis proxy example:

1. cp examples/redis.lua path-to-nginx/conf
2. vi nginx.conf add:

     tcp {
         server {
             listen 8000;
             process_by_lua_file conf/redis.lua;
         }
     }

3. run redis on default port
    
    redis-server

4. issue a redis-benchmark test:

    redis-benchmark -q -p 8000 -c 200 -n 100000 

Copyright and License
===========

    This module is licensed under the BSD license.

    Copyright (C) 2012-, by Simon LEE(bigplum@gmail.com).

    All rights reserved.

    Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

    Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

    Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
    USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

See Also
============

*[lua-nginx-module](https://github.com/chaoslawful/lua-nginx-module)

