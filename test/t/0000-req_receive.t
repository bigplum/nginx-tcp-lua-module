use Test::Nginx::Socket;
repeat_each(1);
plan tests => 1 * repeat_each() * blocks();

run_tests();

__DATA__

=== TEST 1: receive()
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
            ngx.print(re)
        ';
    }
}
--- raw_request
foooooo
--- raw_response: foooooo

=== TEST 2: receive(10)
--- config 
--- main_config 
tcp {
    server {
        listen 1980;
        process_by_lua '
            local sock = ngx.req.socket()
            local re = sock:receive(10)
            if re == nil then
                ngx.print("error")
            end
            ngx.print(re)
        ';
    }
}
--- raw_request
foofoofoofoo
--- raw_response: foofoofoof

=== TEST 3: receive("*l")
--- config 
--- main_config 
tcp {
    server {
        listen 1980;
        process_by_lua '
            local sock = ngx.req.socket()
            local re = sock:receive("*l")
            if re == nil then
                ngx.print("error")
            end
            ngx.print(re)
        ';
    }
}
--- raw_request
foofoofoofoo
--- raw_response: foofoofoofoo

