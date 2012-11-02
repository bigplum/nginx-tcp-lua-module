use Test::Nginx::Socket;
repeat_each(1);
plan tests => 1 * repeat_each() * blocks();

run_tests();

__DATA__

=== TEST 1: connect()
--- config 
--- main_config 
tcp {
    server {
        listen 1980;
        process_by_lua '
            local sock = ngx.socket.tcp()
            local req = ngx.req.socket()
            local re = req:receive()

            local rt = sock:connect("127.0.0.1",1984)
            if rt == nil then
                ngx.say("error")
            end
            ngx.say(re)
        ';
    }
}
--- raw_request
foooooo
--- raw_response
foooooo

=== TEST 2: connect() fail
--- config 
--- main_config 
tcp {
    server {
        listen 1980;
        process_by_lua '
            local sock = ngx.socket.tcp()
            local req = ngx.req.socket()
            local re = req:receive()

            local rt = sock:connect("127.0.0.1",1985)
            if rt == nil then
                ngx.say("error")
            end
            ngx.say(re)

            local rt,err = sock:send("GET / HTTP/1.1\\r\\n\\r\\n\\r\\n")
            if rt == nil then
                ngx.say(err)
            end
            ngx.say(rt)

            rt, err = sock:receive()
            if rt == nil then
                ngx.say(err)
            end
            ngx.say(rt)
        ';
    }
}
--- raw_request
foooooo
--- raw_response
error
foooooo
closed
nil
closed
nil

=== TEST 3: resolve hostname
--- config 
--- main_config 
tcp {
    server {
        listen 1980;
        resolver 8.8.8.8;
        process_by_lua '
            local sock = ngx.socket.tcp()
            local req = ngx.req.socket()
            local re = req:receive()

            local rt, err = sock:connect("baidu.com",80)
            if rt == nil then
                ngx.say("error")
            end
            ngx.say(re)
            
            rt, err = sock:close()
            ngx.say(rt,err)
        ';
    }
}
--- raw_request
foooooo
--- raw_response
foooooo
1nil

=== TEST 4: no resolver 
--- config 
--- main_config 
tcp {
    server {
        listen 1980;
        process_by_lua '
            local sock = ngx.socket.tcp()
            local req = ngx.req.socket()
            local re = req:receive()

            local rt,err = sock:connect("baidu.com",80)
            if rt == nil then
                ngx.say(err)
            else
                ngx.say(re)
            end

            local bytes, err = sock:send(re)
            if not bytes then
                ngx.say("failed to send request: ", err)
            end

            ngx.say("request sent: ", bytes)

            rt, err = sock:close()
            ngx.say(rt,err)
        ';
    }
}
--- raw_request
foooooo
--- raw_response
no resolver defined to resolve "baidu.com"
failed to send request: closed
request sent: nil
nilclosed

=== TEST 5: send()
--- config 
--- main_config 
tcp {
    server {
        listen 1980;
        resolver 8.8.8.8;
        process_by_lua '
            local sock = ngx.socket.tcp()
            local req = ngx.req.socket()
            local re = req:receive()

            local rt = sock:connect("baidu.com",80)
            if rt == nil then
                ngx.say("error")
            end
            local rt,err = sock:send("GET / HTTP/1.1\\r\\n\\r\\n\\r\\n")
            if rt == nil then
                ngx.say(err)
            end
            ngx.say(rt)

            rt = sock:receive()
            if rt == nil then
                ngx.say(err)
            end
            ngx.say(rt)
            rt = sock:receive()
            if rt == nil then
                ngx.say(err)
            end
            rt = sock:receive()
            if rt == nil then
                ngx.say(err)
            end
            ngx.say(rt)

            rt, err = sock:close()
            ngx.say(rt,err)
        ';
    }
}
--- raw_request
foooooo
--- raw_response
20
HTTP/1.1 400 Bad Request
Server: Apache
1nil

=== TEST 6: resolver fail
--- config 
--- main_config 
tcp {
    server {
        listen 1980;
        resolver 8.8.8.8;
        process_by_lua '
            local sock = ngx.socket.tcp()
            local req = ngx.req.socket()
            local re = req:receive()

            local rt,err = sock:connect("abcd.baidu.com",80)
            if rt == nil then
                ngx.say(err)
            else
                ngx.say(re)
            end

            local bytes, err = sock:send(re)
            if not bytes then
                ngx.say("failed to send request: ", err)
            end

            ngx.say("request sent: ", bytes)

            rt, err = sock:close()
            ngx.say(rt,err)
        ';
    }
}
--- raw_request
foooooo
--- raw_response
abcd.baidu.com could not be resolved (3: Host not found)
failed to send request: closed
request sent: nil
nilclosed

=== TEST 7: resolver timeout
--- config 
--- main_config 
tcp {
    server {
        listen 1980;
        resolver 8.8.8.8;
        resolver_timeout 1ms;
        process_by_lua '
            local sock = ngx.socket.tcp()
            local req = ngx.req.socket()
            local re = req:receive()

            local rt,err = sock:connect("abcd.baidu.com",80)
            if rt == nil then
                ngx.say(err)
            else
                ngx.say(re)
            end

            local bytes, err = sock:send(re)
            if not bytes then
                ngx.say("failed to send request: ", err)
            end

            ngx.say("request sent: ", bytes)

            rt, err = sock:close()
            ngx.say(rt)
        ';
    }
}
--- raw_request
foooooo
--- raw_response
abcd.baidu.com could not be resolved (110: Operation timed out)
failed to send request: closed
request sent: nil
nil

=== TEST 8: connect timeout
--- config 
--- main_config 
tcp {
    server {
        listen 1980;
        resolver 8.8.8.8;
        lua_socket_connect_timeout 1ms;
        process_by_lua '
            local sock = ngx.socket.tcp()
            local req = ngx.req.socket()
            local re = req:receive()

            local rt,err = sock:connect("baidu.com",80)
            if rt == nil then
                ngx.say(err)
            else
                ngx.say(re)
            end

            local bytes, err = sock:send(re)
            if not bytes then
                ngx.say("failed to send request: ", err)
            end

            ngx.say("request sent: ", bytes)

            rt, err = sock:close()
            ngx.say(rt,err)
        ';
    }
}
--- raw_request
foooooo
--- raw_response
timeout
failed to send request: closed
request sent: nil
nilclosed

=== TEST 9: read timeout
--- config 
--- main_config 
tcp {
    server {
        listen 1980;
        resolver 8.8.8.8;
        lua_socket_send_timeout 1ms;
        lua_socket_read_timeout 1ms;
        process_by_lua '
            local sock = ngx.socket.tcp()
            local req = ngx.req.socket()
            local re = req:receive()

            local rt,err = sock:connect("baidu.com",80)
            if rt == nil then
                ngx.say(err)
            end

            local bytes, err = sock:send("GET / HTTP/1.1\\r\\n\\r\\n\\r\\n")
            if not bytes then
                ngx.say("failed to send request: ", err)
            end

            ngx.say("request sent: ", bytes)

            rt,err = sock:receive()
            if rt == nil then
                ngx.say(err)
            end
            ngx.say(rt)

            rt, err = sock:close()
            ngx.say(rt,err)
        ';
    }
}
--- raw_request
foo
--- raw_response
request sent: 20
timeout
nil
nilclosed

=== TEST 10: small buffer size
--- config 
--- main_config 
tcp {
    server {
        listen 1980;
        resolver 8.8.8.8;
        lua_socket_buffer_size 1;
        process_by_lua '
            local sock = ngx.socket.tcp()
            local req = ngx.req.socket()
            local re = req:receive()

            local rt,err = sock:connect("baidu.com",80)
            if rt == nil then
                ngx.say(err)
            end

            local bytes, err = sock:send("GET / HTTP/1.1\\r\\n\\r\\n\\r\\n")
            if not bytes then
                ngx.say("failed to send request: ", err)
            end

            ngx.say("request sent: ", bytes)

            rt, err = sock:receive(8)
            if rt == nil then
                ngx.say(err)
            end
            ngx.say(rt)

            rt, err = sock:close()
            ngx.say(rt,err)
        ';
    }
}
--- raw_request
foo
--- raw_response
request sent: 20
HTTP/1.1
1nil

