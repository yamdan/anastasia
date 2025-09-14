## How to setup circuits

TBD

## Note

Add `max_extra_extension_len` to circuit JSON file like:

```jsonc
{"noir_version":"1.0.0-beta.8+b33131574388d836341cea9b6380f3b1a8493eb8","max_extra_extension_len":500,
//...
}
```

The value must equal to the `MAX_EXTRA_EXT_LEN` in the corresponding Noir circuit like:

```rust
global MAX_EXTRA_EXT_LEN: u32 = 500;
```
