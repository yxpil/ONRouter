;; body_filter：把响应体读进 guest 内存，只保留前 5 个字节再写回去。
;; 截断比"整段替换成常量"更能证明插件真的看到了上游的体（前 5 字节来自上游）。
(module
  (import "env" "host_read_into" (func $read (param i32 i32 i32 i32 i32) (result i32)))
  (import "env" "host_set_body" (func $set (param i32 i32) (result i32)))
  (memory (export "memory") 1)
  (func (export "on_body_filter") (result i32)
    i32.const 1024
    i32.const 7 i32.const 0 i32.const 0 i32.const 1024 i32.const 4096 call $read
    i32.const 5 i32.gt_s
    if (result i32)
      i32.const 5
    else
      i32.const 0
    end
    call $set drop
    i32.const 0))
