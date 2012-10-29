use Test::Nginx::LWP;
repeat_each(1);
plan tests => 2 * repeat_each() * blocks();

run_tests();

__DATA__

=== TEST 1: read request
--- config 
--- main_config 
tcp {
    server {
        listen 1980;
        process_by_lua '
            sock = ngx.req.socket()
            local re = sock:receive()
            if re == nil then
                ngx.print("error")
            end
            ngx.print(re)
        ';
    }
}
--- request
fooooooo
--- response_headers_like
fooooooo


