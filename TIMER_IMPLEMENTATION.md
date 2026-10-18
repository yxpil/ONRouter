# ngx.timer API Implementation (aligned with OpenResty official E2E semantics)

## Overview

Implemented OpenResty-compatible background timer APIs for ONRouter. The implementation was **analyzed against the official
lua-nginx-module test suite** (cloned to `vendor/lua-nginx-module/t/`, 193 E2E files) and reworked to match the semantics
asserted by `t/106-timer.t`, `t/152-timer-every.t`, `t/107-timer-errors.t`.

## API (official-compatible)

```lua
local ok, err = ngx.timer.at(0.05, function(premature, arg1, arg2)
    -- delay unit: SECONDS (float), first arg: premature flag, rest: user args forwarded verbatim
end, arg1, arg2)

local ok, err = ngx.timer.every(0.1, cb)   -- interval <= 0 -> (nil, "invalid interval")
                                            -- cb returns false explicitly -> loop stops
ngx.timer.pending_count()                  -- capped at 1024 (lua_max_pending_timers)
ngx.timer.running_count()                  -- capped at 4096 (lua_max_running_timers)
```

Error returns (matching official strings asserted by the suite):
- `"invalid delay"` — non-numeric or negative
- `"invalid callback type"` — non-function callback
- `"invalid interval"` — every() with interval <= 0
- `"too many pending timers"` — pending cap

## Thread-Safety Model (key fix from the analysis)

Earlier drafts called `callback.call()` from the timer task without holding the VM lock, and left `__ctx` pointing at
whatever request last used that VM. The official suite (timer + lua_code_cache + shared upvalue tests) exposes both as
crosstalk/UB. Current design:

1. Each VM is `Arc<tokio::sync::Mutex<Lua>>`; `install_api` receives a `Weak<VM>` handle.
2. At registration the user args are frozen into a Lua table (`{1..n, n=cnt}`) and the `Function` is moved into the task
   (valid because mlua has the `send` feature).
3. When firing, the task **acquires its own VM's lock**, swaps `__ctx` to a **detached RequestCtx**
   (`RequestCtx::detached()` — OpenResty's "fake request client") and fresh `ngx.ctx`, then dispatches via the
   `__timer_dispatch` registry helper: `f(premature, table.unpack(args, 1, args.n))`.
4. `pending`/`running` counters are `Arc<AtomicIsize>` shared process-wide.

## Known Divergence from OpenResty

- **Timer latency under busy VM**: run_phase holds the VM mutex across awaits (e.g. `ngx.sleep`), so timer callbacks on the
  same VM cannot interleave mid-await the way OpenResty's single-threaded coroutine scheduler allows. Callbacks queue and
  fire correctly once the lock frees. True coroutine-level interleaving needs mlua async-coroutine plumbing (v0.4).
- `premature` is always `false` on normal fire; premature-on-shutdown delivery is not yet wired into graceful stop.
- No `ngx.timer` cancellation (`pending` timers can't be killed).

## E2E Verification

`timer_e2e_test.py` ports assertions directly from the official suite:

| Ported check | Source |
|---|---|
| at fires with premature=false | t/106-timer.t TEST 1 |
| user args forwarded verbatim | t/106-timer.t TEST 9 |
| every fires with premature arg | t/152-timer-every.t TEST 1 |
| callback `return false` stops loop | OpenResty v0.10.6 every() semantics |
| pending_count reflects queue | t/136-timer-counts.t |
| invalid delay/callback/interval -> (nil, err) | t/107-timer-errors.t |
| no [error] log crosstalk | every official `--- no_error_log` |

```
$ python timer_e2e_test.py
PASS x11 -> 11/11 通过
```

## Running the Official Suite (reference)

Full `.t` files require Test::Nginx (Perl: `Test::Base`, `Test::LongString`) **and an OpenResty binary** as
`TEST_NGINX_BINARY`; they cannot execute against ONRouter today because they also rely on `*_by_lua_block` config syntax,
the `echo` directive, and Unix signals. The suite is vendored under `vendor/lua-nginx-module/` (gitignored) as the
canonical semantics reference for porting more cases.
