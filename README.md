nginx tcp lua module
=============
A tcp module with lua support for nginx.

Most code are copied from ngx-lua-module, and APIs are planed to 
be compatible with ngx-lua module. 

Thanks for great job of ngx-lua module.

Usage
============

This module is under heavy development.

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

