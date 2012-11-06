use Test::Nginx::Socket;
repeat_each(1);
plan tests => 2 * repeat_each() * blocks();

run_tests();

__DATA__

=== TEST 1: test log-level STDERR
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
             ngx.say("before log")
             ngx.log(ngx.STDERR, "hello, log", 1234, 3.14159)
             ngx.say("after log")
        ';
    }
}
--- raw_request
foooooo
--- raw_response
before log
after log
--- error_log eval
qr/\[\] \S+: \S+ \[lua\] \[string "process_by_lua"\]:8: hello, log12343.14159/

=== TEST 2: test log-level EMERG
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
             ngx.say("before log")
             ngx.log(ngx.EMERG, "hello, log", 1234, 3.14159)
             ngx.say("after log")
        ';
    }
}
--- raw_request
foooooo
--- raw_response
before log
after log
--- error_log eval
qr/\[emerg\] \S+: \S+ \[lua\] \[string "process_by_lua"\]:8: hello, log12343.14159/

=== TEST 3: test log-level ALERT
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
             ngx.say("before log")
             ngx.log(ngx.ALERT, "hello, log", 1234, 3.14159)
             ngx.say("after log")
        ';
    }
}
--- raw_request
foooooo
--- raw_response
before log
after log
--- error_log eval
qr/\[alert\] \S+: \S+ \[lua\] \[string "process_by_lua"\]:8: hello, log12343.14159/

=== TEST 4: test log-level CRIT
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
             ngx.say("before log")
             ngx.log(ngx.CRIT, "hello, log", 1234, 3.14159)
             ngx.say("after log")
        ';
    }
}
--- raw_request
foooooo
--- raw_response
before log
after log
--- error_log eval
qr/\[crit\] \S+: \S+ \[lua\] \[string "process_by_lua"\]:8: hello, log12343.14159/

=== TEST 5: test log-level ERR 
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
             ngx.say("before log")
             ngx.log(ngx.ERR, "hello, log", 1234, 3.14159)
             ngx.say("after log")
        ';
    }
}
--- raw_request
foooooo
--- raw_response
before log
after log
--- error_log eval
qr/\[error\] \S+: \S+ \[lua\] \[string "process_by_lua"\]:8: hello, log12343.14159/

=== TEST 6: test log-level WARN
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
             ngx.say("before log")
             ngx.log(ngx.WARN, "hello, log", 1234, 3.14159)
             ngx.say("after log")
        ';
    }
}
--- raw_request
foooooo
--- raw_response
before log
after log
--- error_log eval
qr/\[warn\] \S+: \S+ \[lua\] \[string "process_by_lua"\]:8: hello, log12343.14159/

=== TEST 7: test log-level NOTICE
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
             ngx.say("before log")
             ngx.log(ngx.NOTICE, "hello, log", 1234, 3.14159)
             ngx.say("after log")
        ';
    }
}
--- raw_request
foooooo
--- raw_response
before log
after log
--- error_log eval
qr/\[notice\] \S+: \S+ \[lua\] \[string "process_by_lua"\]:8: hello, log12343.14159/

=== TEST 8: test log-level INFO
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
             ngx.say("before log")
             ngx.log(ngx.INFO, "hello, log", 1234, 3.14159)
             ngx.say("after log")
        ';
    }
}
--- raw_request
foooooo
--- raw_response
before log
after log
--- error_log eval
qr/\[info\] \S+: \S+ \[lua\] \[string "process_by_lua"\]:8: hello, log12343.14159/

=== TEST 9: test log-level DEBUG
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
             ngx.say("before log")
             ngx.log(ngx.DEBUG, "hello, log", 1234, 3.14159)
             ngx.say("after log")
        ';
    }
}
--- raw_request
foooooo
--- raw_response
before log
after log
--- error_log eval
qr/\[debug\] \S+: \S+ \[lua\] \[string "process_by_lua"\]:8: hello, log12343.14159/

=== TEST 10: test print
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
             ngx.say("before log")
             print("hello, log", 1234, 3.14159)
             ngx.say("after log")
        ';
    }
}
--- raw_request
foooooo
--- raw_response
before log
after log
--- error_log eval
qr/\[notice\] \S+: \S+ \[lua\] \[string "process_by_lua"\]:8: hello, log12343.14159/

