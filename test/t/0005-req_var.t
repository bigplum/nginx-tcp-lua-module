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
		error_log  /root/nginx/ngx-moomin-bundle/nginx-tcp-lua-module/test/req_var.log;
        process_by_lua '
            local sock = ngx.req.socket()
            local re = sock:receive()
            if re == nil then
                ngx.print("error")
            end
            ngx.print(ngx.var.remote_addr)
        ';
    }
}
--- raw_request
foooooo
--- raw_response: 127.0.0.1

