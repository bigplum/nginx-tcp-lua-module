
local req = ngx.req.socket()
local upsock = ngx.socket.tcp()

local rt, err = upsock:connect("127.0.0.1", 6379)
if not rt then
    ngx.say("failed to connect: ", err)
    return
end

local r, i, buf, cnt, s
local t 
while true do
    local rt, err = req:receive()
    if not rt then
        ngx.log(ngx.DEBUG, "failed to recv req: ".. err)
        break
    end

    r = rt:byte(1,1)
    cnt = 0
    if r == 42 then    -- *
        cnt = tonumber(rt:sub(2))
    else
        ngx.log(ngx.DEBUG, "read a non * line")
        cnt = 0
    end
    buf = rt.."\r\n"

    i = 1
    while i <= cnt * 2 do
        rt, err = req:receive()
        if not rt then
            ngx.log(ngx.ERR, "failed to recv req: " .. err)
            break
        end
        buf = buf..rt.."\r\n"
        i = i + 1
    end

    rt, err = upsock:send(buf)
    if not rt then
        ngx.say("failed to send: ", err)
        break
    end

    rt, err = upsock:receive()
    if not rt then
        ngx.log(ngx.ERR, "failed to recv first resp: " .. err)
        break
    end

    r = rt:byte(1,1)
    cnt = 0
    buf = rt.."\r\n"

    if  r == 42 then    -- *
        cnt = tonumber(rt:sub(2))
    elseif r == 36 then  -- $
        s = rt:byte(2,2)
        if s ~= 45 then  -- -
            rt, err = upsock:receive()
            if not rt then
                ngx.log(ngx.ERR, "failed to recv single resp: " .. err)
                break
            end
            buf = buf..rt.."\r\n"
        end
    end

    i = 1
    while i <= cnt * 2 do
        rt, err = upsock:receive()
        if not rt then
            ngx.log(ngx.ERR, "failed to recv resp: ".. err)
            break
        end
        buf = buf..rt.."\r\n"
        i = i + 1
    end

    ngx.print(buf)
end

rt, err = upsock:setkeepalive(0, 300)
if not rt then
    ngx.log(ngx.ERR, "failed to set keepalive: ".. err)
    return
end
