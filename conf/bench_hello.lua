-- A/B 压测用：ONRouter 与 OpenResty 读同一个绝对路径，专门测 *_file 指令的每请求开销。
-- 只用单参数 ngx.say，避开两侧多参数分隔符的语义差异，保证响应字节可逐字对比。
local name = "hello-from-lua-file"
ngx.say(name)
ngx.say("method=" .. ngx.req.get_method())
