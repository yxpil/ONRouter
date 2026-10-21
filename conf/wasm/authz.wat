;; access 阶段：有 X-Gateway-Token 就放行并给上游加一个已认证头，没有就 403。
;; 这是网关插件最常见的形态——认证在边缘做，业务只信任网关写下的头。
(module
  (import "env" "host_read_len" (func $len (param i32 i32 i32) (result i32)))
  (import "env" "host_set_header" (func $set (param i32 i32 i32 i32 i32) (result i32)))
  (import "env" "host_set_status" (func $status (param i32)))
  (import "env" "host_set_body" (func $body (param i32 i32) (result i32)))
  (memory (export "memory") 1)
  ;; 0:   "X-Gateway-Token"  (15)
  ;; 32:  "X-Wasm-Verified"  (15)
  ;; 64:  "1"
  ;; 96:  "wasm denied: token required" (27)
  (data (i32.const 0) "X-Gateway-Token")
  (data (i32.const 32) "X-Wasm-Verified")
  (data (i32.const 64) "1")
  (data (i32.const 96) "wasm denied: token required")
  (func (export "on_access") (result i32)
    i32.const 4 i32.const 0 i32.const 15 call $len
    i32.const 0 i32.gt_s
    if (result i32)
      i32.const 4 i32.const 32 i32.const 15 i32.const 64 i32.const 1 call $set drop
      i32.const 0
    else
      i32.const 403 call $status
      i32.const 96 i32.const 27 call $body drop
      i32.const 1
    end))
