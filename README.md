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
$ python test/budget.py       # Test resource budgets.
$ python test/spec.py         # Test spec.
$ python test/wasi.py         # Test wasi.
```

# Resource budget

Untrusted modules can be capped before they are decoded or instantiated by passing a
`Budget` to the `instance*` entry points. Three independent limits are enforced across
both phases; a `None` limit means unlimited, and omitting the budget keeps the historical
behavior unchanged.

- `input_bytes`: every byte is reserved against the limit before it is read, so an
  oversized section is rejected without being buffered.
- `struct_entries`: structural items (types, functions, globals, exports, elements,
  data segments, locals and instructions) are reserved before their objects are built.
- `planned_allocations`: the runtime objects admission would create are reserved up
  front, including one unit per store entry plus one per memory page and table element.

When a limit is crossed, `pywasm.BudgetExceeded` is raised with a stable `reason` taken
from `pywasm.Reason` (`input_bytes_exceeded`, `struct_entries_exceeded`,
`planned_allocations_exceeded`). Rejections happen before the offending structure is
created, and any store entries already built during a failed admission are rolled back.

```py
import pywasm

budget = pywasm.Budget(input_bytes=1 << 20, struct_entries=10_000,
                       planned_allocations=100_000)
runtime = pywasm.core.Runtime()
try:
    module = runtime.instance_from_file('untrusted.wasm', budget)
except pywasm.BudgetExceeded as e:
    print(f'rejected: {e.reason} (used={e.used}, requested={e.requested})')
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
