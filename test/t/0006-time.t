use Test::Nginx::Socket;
repeat_each(1);
plan tests => 2 * repeat_each() * blocks();

run_tests();

__DATA__


=== TEST 1: tcp_time in process_by_lua
--- config
--- main_config 
tcp {
    server {
        listen 1980;
        process_by_lua '
            local sock = ngx.req.socket()
            local re = sock:receive()
            if re == nil then
                ngx.print("error")
            end
            ngx.say(ngx.tcp_time(1290079655))
        ';
    }
}
--- raw_request
GET /lua
--- raw_response
Thu, 18 Nov 2010 11:27:35 GMT



=== TEST 4: parse_tcp_time in process_by_lua
--- config
--- main_config 
tcp {
    server {
        listen 1980;
        process_by_lua '
            local sock = ngx.req.socket()
            local re = sock:receive()
            if re == nil then
                ngx.print("error")
            end
            ngx.say(ngx.parse_tcp_time("Thu, 18 Nov 2010 11:27:35 GMT"))
            ';
    }
}
--- raw_request
GET /lua
--- raw_response
1290079655



=== TEST 5: bad arg for parse_tcp_time in process_by_lua
--- config
--- main_config 
tcp {
    server {
        listen 1980;
        process_by_lua '
            local sock = ngx.req.socket()
            local re = sock:receive()
            if re == nil then
                ngx.print("error")
            end
            ngx.say(ngx.parse_tcp_time("abc") or "nil")
            ';
    }
}
--- raw_request
GET /lua
--- raw_response
nil
