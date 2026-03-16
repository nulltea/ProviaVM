# zkPassport

## Run

### Deploy test infra

```bash
RUST_LOG=trace REUSE_PREPROC=1 TRACY_CAPTURE=1 bash examples/deploy.sh
```

### Run example delegate (generated fixture)

```bash
RUSTFLAGS="-A warnings" cargo run --manifest-path examples/zkpassport/Cargo.toml -- \
  --generate \
  --native-only
```
