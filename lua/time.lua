-- time.lua：演示外部 Lua 文件 + 异步 ngx.sleep + ngx.ctx 跨阶段状态
ngx.ctx.entered = ngx.ctx.entered or ngx.now()
ngx.sleep(0.02)  -- 协程让出 20ms，不阻塞 worker（冒烟测试的超时是 10s）
ngx.header["Content-Type"] = "application/json"
local now = os.date("!%Y-%m-%dT%H:%M:%SZ")
ngx.say(string.format('{"now": "%s", "elapsed_ms": %.2f}', now, (ngx.now() - ngx.ctx.entered) * 1000))
