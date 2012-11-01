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
                ngx.print("error")
            end
            ngx.print(re)
        ';
    }
}
--- raw_request
foooooo
--- raw_response: foooooo

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
                ngx.print("error")
            end
            ngx.print(re)
        ';
    }
}
--- raw_request
foooooo
--- raw_response: errorfoooooo

=== TEST 3: connect() resolve hostname
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
                ngx.print("error")
            end
            ngx.print(re)
        ';
    }
}
--- ONLY
--- raw_request
foooooo
--- raw_response: foooooo

