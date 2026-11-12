# Pywasm: A WebAssembly interpreter written in pure Python.

A WebAssembly interpreter written in pure Python, no third-party libraries are used.

![img](./res/pywasm.jpg)

The `wasm` version currently in use is: [WebAssembly Specification, Release 2.0 (Draft 2025-04-25)](https://webassembly.github.io/spec/core/).

The `wasi` version currently in use is: [WASI Preview 1](https://github.com/WebAssembly/WASI/blob/main/legacy/README.md).

Also requires Python version >= 3.12.

# Installation

```sh
$ pip install pywasm
```

# Some simple examples

1. First we need a wasm module! Grab our `example/fibonacci/bin/fibonacci.wasm` file and save a copy in a new directory on your local machine.

2. Now, instantiate WebAssembly modules directly from underlying sources. This is achieved using the `Runtime.instance_from_file` method.

```py
import pywasm
pywasm.log.lvl = 1

runtime = pywasm.core.Runtime()
m = runtime.instance_from_file('example/fibonacci/bin/fibonacci.wasm')
r = runtime.invocate(m, 'fibonacci', [10])
print(f'fibonacci(10) = {r[0]}')
```

A brief description for `example`

|           File            |                             Description                              |
| ------------------------- | -------------------------------------------------------------------- |
| example/blake2b.py        | Blake2b hashing algorithm                                            |
| example/blake2b_direct.py | Make the hash result returned as a value, not as an output parameter |
| example/blake2b_iter.py   | A benchmarking example using the blake2b hash function               |
| example/blake2b_simd.py   | Use SIMD instructions to accelerate the blake2b hash function        |
| example/fibonacci.py      | Fibonacci, which contains loop and recursion                         |
| example/fibonacci_env.py  | Call python/native function in wasm                                  |
| example/pi.py             | Calculate π using the agm algorithm                                  |
| example/wasi_httpbin.py   | Execute a wasi program and http get from <http://httpbin.org>        |
| example/wasi_ll.py        | Execute a wasi program and list information about a directory        |
| example/wasi_stdout.py    | Execute a wasi program and capture stdout                            |
| example/wasi_zen.py       | Execute a wasi program and print poem "The Zen of Python"            |

# Test

```sh
$ python script/build_wabt.py # Download wabt tools at res/wabt.
$ python script/build_spec.py # Download spec tests at res/spec.
$ python script/build_wasi.py # Download wasi tests at res/wasi-testsuite.

$ python test/example.py      # Test example.
$ python test/main.py         # Test main.
$ python test/spec.py         # Test spec.
$ python test/wasi.py         # Test wasi.
```

# Performance

Pywasm is an interpreter implemented using pure python and its standard library, capable of running on any python platform. Due to the inherent characteristics of python, you should not have overly high expectations for pywasm's performance.

However, pywasm's design makes it jit-friendly. Compared to cpython, pywasm's performance on [pypy](https://pypy.org/) can improve by approximately 10 times, significantly surpassing the average 3-fold improvement.

# Thanks

- [wagon](https://github.com/go-interpreter/wagon)
- [warpy](https://github.com/kanaka/warpy)
- [zstdpy](https://github.com/dholth/zstdpy)

# License

[MIT](./LICENSE)

# Reusing one host across isolated WASI tasks

`pywasm.wasi.Host` keeps one interpreter runtime and one host-function table while giving every task its own
arguments, environment, preopened directories, and file-descriptor table. Tasks are entered explicitly and are
revoked on every exit path: normal return, `proc_exit`, or a guest exception.

```py
import pywasm

host = pywasm.wasi.Host()
task = host.task(['app.wasm', '--name', 'second'], {'/data': '/tmp/job-data'}, {'FAKE_SECRET': 'second'})
exit_code = host.run(task, 'app.wasm')
assert task.revoked
```

- `Host()` owns the `pywasm.core.Runtime` and the wasi host function table. It never restarts the process.
- `Host.task(args, dirs, envs, shared_dirs=...)` snapshots the task inputs. Nothing another task sets is
  observable: every host function resolves the active task from a context-local stack and fails closed with
  `TaskNotActiveError`/`TaskRevokedError` when none is active.
- `Host.run(task, module_or_path, func='_start')` enters the task, instantiates a fresh module instance, invokes
  the entry point, and always exits in `finally`. `proc_exit` returns its code; other exceptions propagate after
  the task is revoked. `Host.invocate` runs a non-`_start` export under the same boundary.
- Use `task.enter()` / `task.exit()` (or `with host.task(...) as task:`) when you need explicit control. `exit()`
  is idempotent and also revokes. A revoked task raises `TaskRevokedError` if used again; it can never fall back
  to another task's table. Direct-mode `Preview1` instances remain single-use: `Preview1.main()` revokes them too.

Ownership:

- The host owns the runtime; a task owns descriptors it opens through `path_open` and its read-write preopens,
  and closes them on revocation. Process `stdin`/`stdout`/`stderr` stay owned by the embedding process.
- `SharedDir(wasm_name, host_path, owner)` is an explicit, caller-owned, read-only resource. Declare it with
  `shared_dirs={'/assets': sd}`; tasks borrow a lease and the host never closes it. `SharedDir.close()` refuses
  while a task lease is active, and everything opened beneath a shared preopen inherits its read-only restriction.
- Modules are pinned to the task that instantiated them; a module handle cannot be invoked under a different
  task. One module instance per task also keeps guest memory and globals from surviving between runs.
- One `Host` runs tasks sequentially. A `pywasm.core.Runtime` has a single machine/store, so use one `Host` per
  concurrently executing guest. Binding a second `Host` to an already owned runtime raises `TaskConflictError`.
- CLI usage (`python -m pywasm --wasi preview1 ...`) and the existing `Preview1(args, dirs, envs)` flow still
  work; those direct-mode instances are single-use because `Preview1.main()` revokes them.
