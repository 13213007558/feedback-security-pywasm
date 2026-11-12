# Feedback task starting environment

Upstream: https://github.com/libraries/pywasm
Upstream commit: `9ab33f8a420224cba34cb5a1c8a550e189ef2211`
Prepared on macOS with the Python version recorded in the environment plan. No external database, queue, or cloud account is required.

The dependency file pins the installed runtime and test packages for the selected baseline. It is not a claim that all optional upstream test suites are installed.

From the repository root:

```sh
export NO_INTERNET=1 TZ=UTC UV_NO_CONFIG=1

uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -c 'import pywasm; r=pywasm.core.Runtime(); m=r.instance_from_file('"'"'example/fibonacci/bin/fibonacci.wasm'"'"'); actual=[r.invocate(m,'"'"'fibonacci'"'"',[n])[0] for n in (0,1,2,5,10)]; assert actual==[0,1,1,5,55],actual; print('"'"'5 real Wasm invocations passed'"'"')'
```

Scope note: The scope is the command below, not all optional upstream integrations.

Observed baseline (2026-11-12): `5 real Wasm invocations passed`
Whole-command wall time: 0.046 seconds, exit code 0. This is one local measurement, not a runtime guarantee. The first install is excluded.

This seed adds preparation metadata only. Application sources and upstream tests are unchanged; there is no task solution in this commit.
