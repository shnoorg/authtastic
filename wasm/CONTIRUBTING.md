# Contributing

## Dependencies

```bash
## wasm-pack
curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
```

## Build

```bash
wasm-pack build --release --scope authtastic --out-name index --target web
```

## Publish

```bash
wasm-pack publish pkg --access public
```