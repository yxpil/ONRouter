;; 死循环：用来证明 fuel 预算真的会拦住插件，而不是把工作线程挂死。
(module
  (memory (export "memory") 1)
  (func (export "on_access") (result i32)
    loop $spin
      br $spin
    end
    i32.const 0))
