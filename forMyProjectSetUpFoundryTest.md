### when folders are related projects that should be compile together share lib and run in a single forge test

## 1. create a single root level foundry project by running this command to init the project as root:

forge init . --no-git --force

## 2. adding this to cargo.toml:
```toml
[profile.default]
# Compiled byte-code & ABI output
out = "out"
# All import search paths
libs = [
    # ⬇ add a glob so every A-Z folder becomes a library path
    "lib",
    "?",        # built-in alias for root (optional)
    "*/"        # ← picks up A/, B/, C/, … Z/
]

# If every letter folder keeps code in a nested src/ subdir
# (e.g. A/src/MyA.sol), let Foundry know:
sources = [
    "./src",     # root src (optional)
    "*/src"      # glob over A/src, B/src, …
]
```

### run everything from the root

