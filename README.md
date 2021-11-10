## Build sel4_teeos

Go to build dir.

```
$ cmake -G Ninja -DCROSS_COMPILER_PREFIX=<absolute_path_to_toolchain+prefix> ../projects/seL4_teeos
$ ninja
```

e.g. CROSS_COMPILER_PREFIX=/path_to_toolchain/bin/riscv64-unknown-linux-gnu-

"kernel + rootserver + communication app" image is located in `<build_dir>/images/teeos_root-image-riscv-polarfire`

Standalone HSS payload image is created in `<build_dir>/gen_hss_payload/payload.bin`. It includes only seL4 payload.
