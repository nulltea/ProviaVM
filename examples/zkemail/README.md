# zkEmail

## Run

### Deploy test infra

```bash
RUST_LOG=trace REUSE_PREPROC=1 TRACY_CAPTURE=1 bash examples/deploy.sh
```

### Run example delegate

```bash
RUSTFLAGS="-A warnings" cargo run --manifest-path examples/zkemail/Cargo.toml -- \
  --email-path examples/zkemail/test-emails/gmail.eml \
  --from-domain gmail.com \
  --profile-rsa
```

## Test
```
cargo test --manifest-path examples/zkemail/Cargo.toml --test prove_correct -- --nocapture
```
