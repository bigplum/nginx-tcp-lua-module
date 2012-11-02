use Test::Nginx::Socket;
repeat_each(1);
plan tests => 4 * repeat_each() * blocks() + 1;

run_tests();

__DATA__

=== TEST 1: sanity
--- config 
--- main_config 
tcp {
    lua_package_path 't/servroot/html/?.lua;./?.lua';
    server {
        listen 1980;
        process_by_lua '
            local test = require "test"

            local req = ngx.req.socket()
            req:receive()

            test.go(11211)
            test.go(11211)
        ';
    }
}
--- user_files
>>> test.lua
module("test", package.seeall)

function go(port)
    local sock = ngx.socket.tcp()
    local ok, err = sock:connect("127.0.0.1", port)
    if not ok then
        ngx.say("failed to connect: ", err)
        return
    end

    ngx.say("connected: ", ok, ", reused: ", sock:getreusedtimes())

    local req = "flush_all\r\n"

    local bytes, err = sock:send(req)
    if not bytes then
        ngx.say("failed to send request: ", err)
        return
    end
    ngx.say("request sent: ", bytes)

    local line, err, part = sock:receive()
    if line then
        ngx.say("received: ", line)

    else
        ngx.say("failed to receive a line: ", err, " [", part, "]")
    end

    local ok, err = sock:setkeepalive()
    if not ok then
        ngx.say("failed to set reusable: ", err)
    end
end
--- raw_request
foooooo
--- raw_response
connected: 1, reused: 0
request sent: 11
received: OK
connected: 1, reused: 1
request sent: 11
received: OK
--- no_error_log eval
["[error]",
"lua socket keepalive: free connection pool for "]
--- error_log eval
qq{lua socket get keepalive peer: using connection
lua socket keepalive create connection pool for key "127.0.0.1:11211"
}

=== TEST 2: free up the whole connection pool if no active connections
--- config 
--- main_config 
tcp {
    lua_package_path 't/servroot/html/?.lua;./?.lua';
    server {
        listen 1980;
        process_by_lua '
            local test = require "test"

            local req = ngx.req.socket()
            req:receive()

            test.go(11211, true)
            test.go(11211, false)
        ';
    }
}
--- user_files
>>> test.lua
module("test", package.seeall)

function go(port, keepalive)
    local sock = ngx.socket.tcp()
    local ok, err = sock:connect("127.0.0.1", port)
    if not ok then
        ngx.say("failed to connect: ", err)
        return
    end

    ngx.say("connected: ", ok, ", reused: ", sock:getreusedtimes())

    local req = "flush_all\r\n"

    local bytes, err = sock:send(req)
    if not bytes then
        ngx.say("failed to send request: ", err)
        return
    end
    ngx.say("request sent: ", bytes)

    local line, err, part = sock:receive()
    if line then
        ngx.say("received: ", line)

    else
        ngx.say("failed to receive a line: ", err, " [", part, "]")
    end

    if keepalive then
        local ok, err = sock:setkeepalive()
        if not ok then
            ngx.say("failed to set reusable: ", err)
        end
    else
        sock:close()
    end
end
--- raw_request
foooooo
--- raw_response
connected: 1, reused: 0
request sent: 11
received: OK
connected: 1, reused: 1
request sent: 11
received: OK
--- no_error_log
[error]
--- error_log eval
["lua socket get keepalive peer: using connection",
"lua socket keepalive: free connection pool for "]



=== TEST 4: http keepalive
--- config
--- main_config 
tcp {
    lua_package_path 't/servroot/html/?.lua;./?.lua';
    server {
        listen 1980;
        process_by_lua '
            local request = ngx.req.socket()
            request:receive()

            local sock = ngx.socket.tcp()

            local ok, err = sock:connect("127.0.0.1", 1984)
            if not ok then
                ngx.say("failed to connect: ", err)
                return
            end

            ngx.say("connected: ", ok)

            local req = "GET / HTTP/1.1\\r\\nHost: localhost\\r\\nConnection: keepalive\\r\\n\\r\\n"

            local bytes, err = sock:send(req)
            if not bytes then
                ngx.say("failed to send request: ", err)
                return
            end

            ngx.say("request sent: ", bytes)

            --local reader = sock:receiveuntil("\\r\\n0\\r\\n\\r\\n")
            local reader = sock:receiveuntil("</html>")
            local data, err = reader()

            if not data then
                ngx.say("failed to receive response body: ", err)
                return
            end

            ngx.say("received response of ", #data, " bytes")

            local ok, err = sock:setkeepalive()
            if not ok then
                ngx.say("failed to set reusable: ", err)
            end

            --ngx.location.capture("/sleep")

            ngx.say("done")
        ';
    }
}

--- raw_request
foo
--- raw_response
connected: 1
request sent: 58
received response of 300 bytes
done
--- no_error_log eval
["[error]",
"lua tcp socket keepalive close handler: fd:",
"lua tcp socket keepalive: free connection pool for "]
--- timeout: 4

