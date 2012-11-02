use Test::Nginx::Socket;
repeat_each(1);
plan tests => 1 * repeat_each() * blocks();

run_tests();

__DATA__

=== TEST 1: code cache default on
--- config
--- main_config 
tcp {
    server {
        listen 1981;
        lua_code_cache on;
        process_by_lua_file html/test.lua;
    }
    server {
        listen 1982;
        process_by_lua '
            local f = assert(io.open("t/servroot/html/test.lua", "w"))
            f:write("ngx.say(101)")
            f:close()
            ngx.say("updated")
        ';
    }
    server {
        listen 1980;
        process_by_lua '
            local req = ngx.req.socket()
            req:receive()

            local sock = ngx.socket.tcp()
            local rt,err = sock:connect("127.0.0.1", 1981)
            rt, err = sock:send("abcd")
            rt, err = sock:receive()
            ngx.say(rt)
            rt, err = sock:close()

            local sock1 = ngx.socket.tcp()
            local rt,err = sock1:connect("127.0.0.1", 1982)
            rt, err = sock1:send("abcd")
            rt, err = sock1:receive()
            ngx.say(rt)
            rt, err = sock1:close()

            local sock2 = ngx.socket.tcp()
            local rt,err = sock2:connect("127.0.0.1", 1981)
            rt, err = sock2:send("abcd")
            rt, err = sock2:receive()
            ngx.say(rt)
            rt, err = sock2:close()
        ';
    }
}
--- user_files
>>> test.lua
ngx.say(32)
--- raw_request
GET
--- raw_response
32
updated
32


=== TEST 3: code cache explicitly off
--- config
--- main_config 
tcp {
    server {
        listen 1981;
        lua_code_cache off;
        process_by_lua_file html/test.lua;
    }
    server {
        listen 1982;
        process_by_lua '
            local f = assert(io.open("t/servroot/html/test.lua", "w"))
            f:write("ngx.say(101)")
            f:close()
            ngx.say("updated")
        ';
    }
    server {
        listen 1980;
        process_by_lua '
            local req = ngx.req.socket()
            req:receive()

            local sock = ngx.socket.tcp()
            local rt,err = sock:connect("127.0.0.1", 1981)
            rt, err = sock:send("abcd")
            rt, err = sock:receive()
            ngx.say(rt)
            rt, err = sock:close()

            local sock1 = ngx.socket.tcp()
            local rt,err = sock1:connect("127.0.0.1", 1982)
            rt, err = sock1:send("abcd")
            rt, err = sock1:receive()
            ngx.say(rt)
            rt, err = sock1:close()

            local sock2 = ngx.socket.tcp()
            local rt,err = sock2:connect("127.0.0.1", 1981)
            rt, err = sock2:send("abcd")
            rt, err = sock2:receive()
            ngx.say(rt)
            rt, err = sock2:close()
        ';
    }
}
--- user_files
>>> test.lua
ngx.say(32)
--- raw_request
GET
--- raw_response
32
updated
101


=== TEST 4: code cache explicitly off (main level)
--- config
--- main_config 
tcp {
    lua_code_cache off;
    server {
        listen 1981;
        process_by_lua_file html/test.lua;
    }
    server {
        listen 1982;
        process_by_lua '
            local f = assert(io.open("t/servroot/html/test.lua", "w"))
            f:write("ngx.say(101)")
            f:close()
            ngx.say("updated")
        ';
    }
    server {
        listen 1980;
        process_by_lua '
            local req = ngx.req.socket()
            req:receive()

            local sock = ngx.socket.tcp()
            local rt,err = sock:connect("127.0.0.1", 1981)
            rt, err = sock:send("abcd")
            rt, err = sock:receive()
            ngx.say(rt)
            rt, err = sock:close()

            local sock1 = ngx.socket.tcp()
            local rt,err = sock1:connect("127.0.0.1", 1982)
            rt, err = sock1:send("abcd")
            rt, err = sock1:receive()
            ngx.say(rt)
            rt, err = sock1:close()

            local sock2 = ngx.socket.tcp()
            local rt,err = sock2:connect("127.0.0.1", 1981)
            rt, err = sock2:send("abcd")
            rt, err = sock2:receive()
            ngx.say(rt)
            rt, err = sock2:close()
        ';
    }
}
--- user_files
>>> test.lua
ngx.say(32)
--- raw_request
GET
--- raw_response
32
updated
101

=== TEST 5: code cache explicitly off (main level), but override by server
--- config
--- main_config 
tcp {
    lua_code_cache off;
    server {
        listen 1981;
        lua_code_cache on;
        process_by_lua_file html/test.lua;
    }
    server {
        listen 1982;
        process_by_lua '
            local f = assert(io.open("t/servroot/html/test.lua", "w"))
            f:write("ngx.say(101)")
            f:close()
            ngx.say("updated")
        ';
    }
    server {
        listen 1980;
        process_by_lua '
            local req = ngx.req.socket()
            req:receive()

            local sock = ngx.socket.tcp()
            local rt,err = sock:connect("127.0.0.1", 1981)
            rt, err = sock:send("abcd")
            rt, err = sock:receive()
            ngx.say(rt)
            rt, err = sock:close()

            local sock1 = ngx.socket.tcp()
            local rt,err = sock1:connect("127.0.0.1", 1982)
            rt, err = sock1:send("abcd")
            rt, err = sock1:receive()
            ngx.say(rt)
            rt, err = sock1:close()

            local sock2 = ngx.socket.tcp()
            local rt,err = sock2:connect("127.0.0.1", 1981)
            rt, err = sock2:send("abcd")
            rt, err = sock2:receive()
            ngx.say(rt)
            rt, err = sock2:close()
        ';
    }
}
--- user_files
>>> test.lua
ngx.say(32)
--- raw_request
GET
--- raw_response
32
updated
32

