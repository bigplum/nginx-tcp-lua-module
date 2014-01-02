use Test::Nginx::Socket;
repeat_each(1);
plan tests => 2 * repeat_each() * blocks();

run_tests();

__DATA__

=== TEST 1: test base64 encode
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
            local r = ngx.encode_base64("012345678")
            ngx.say(r)
            r = ngx.decode_base64("MDEyMzQ1Njc4")
            ngx.say(r)
        ';
    }
}
--- raw_request
foooooo
--- raw_response
MDEyMzQ1Njc4
012345678

