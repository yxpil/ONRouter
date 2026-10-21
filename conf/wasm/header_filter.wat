;; header_filter：给客户端加一个标记头、删掉上游泄露的内部头、把状态改成 202。
(module
  (import "env" "host_set_header" (func $set (param i32 i32 i32 i32 i32) (result i32)))
  (import "env" "host_del_header" (func $del (param i32 i32 i32) (result i32)))
  (import "env" "host_set_status" (func $status (param i32)))
  (memory (export "memory") 1)
  ;; 0:  "X-Wasm-Header-Filter"  (20)
  ;; 32: "on"
  ;; 48: "X-Backend-Secret"      (16)
  (data (i32.const 0) "X-Wasm-Header-Filter")
  (data (i32.const 32) "on")
  (data (i32.const 48) "X-Backend-Secret")
  (func (export "on_header_filter") (result i32)
    i32.const 5 i32.const 0 i32.const 20 i32.const 32 i32.const 2 call $set drop
    i32.const 5 i32.const 48 i32.const 16 call $del drop
    i32.const 202 call $status
    i32.const 0))
