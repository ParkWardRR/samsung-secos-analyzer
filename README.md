# samsung-secos-analyzer

Analysis tool for Samsung Tizen TV secure OS image partitions (`secos.bin`,
`secos_drv.bin`) and other firmware components from `upgrade.msd` containers.

## What it does

After stripping the MSD container (AES-128-CBC), `secos.bin` and
`secos_drv.bin` remain as opaque `data` blobs — no ELF, uImage, squashfs,
or any recognized magic. This tool maps their internal structure:

- Non-zero block regions and count
- Entropy profiles (16KB windows)
- Block size distributions
- Page alignment analysis
- Visual block maps
- SHA-256 fingerprints
- Magic/header detection for known formats

## What it does NOT do

This tool does **not** decrypt the secure-OS payload. The second encryption
layer is keyed in the TVs BootROM or EL3 monitor. Opening it requires
reversing the secure boot chain (`sboot`), not an offline decryptor.

## Background

Samsung Tizen TV firmware ships as `upgrade.msd` (MSDU11 format). The
container is AES-128-CBC with per-partition salts and a model-specific key.
After decryption, 8 partitions are extracted:

| Partition | After decrypt | Notes |
|---|---|---|
| `uImage` | Linux 4.1.10 ARM kernel | Starts with u-boot magic `27051956` |
| `dtb.bin` | Device tree blob | Starts with `d00dfeed` |
| `platform.img` | VDFS4 rootfs | Samsung proprietary flash FS |
| `secos.bin` | **Opaque** — TrustZone Secure OS | No known header |
| `secos_drv.bin` | **Opaque** — Secure OS driver | No known header |
| `seret.bin` | ARM bootloader | XZ decompressor, boot messages |
| `ddr.init` | DDR PHY training | Maximally random (7.99 entropy) |
| `sign.bin` | Signature block | Different key than MSD |

## Usage

```bash
# Analyze a single file
samsung-secos-analyzer secos.bin

# Analyze multiple files
samsung-secos-analyzer secos.bin secos_drv.bin

# Analyze all known partitions in a directory
samsung-secos-analyzer -all /path/to/extracted/
```

## Build

```bash
go build -o samsung-secos-analyzer .
```

Requires Go 1.22+. No external dependencies.

## Key findings (T-KTMAKUC / KantM 2017)

- `secos.bin`: 2,088,960 bytes, entropy 3.63 bits/byte, 66.2% zeros,
  2,767 non-zero blocks (sparse signed image format)
- `secos_drv.bin`: 1,040,384 bytes (exactly 2:1 ratio), entropy 4.50,
  56% zeros, 1,778 non-zero blocks
- `seret.bin`: ARM code (entry: `mov r3, pc`), XZ decompressor for kernel,
  boot messages, no references to secos/verify/sign
- `onboot.bin`: First-stage bootloader (p0), NOT in `upgrade.msd`

## References

- [msddecrypt](https://github.com/bugficks/msddecrypt) — MSD container decryptor
- [Synacktiv Q60T writeup](https://www.synacktiv.com/sites/default/files/2022-05/Sthack2022_Rooting_Samsung_Q60T_Smart_TV.pdf) — TrustZone key recovery via SWUStandalone
- [unixtract](https://github.com/theubusu/unixtract) — MSD 1.0/1.1 parser
- [Samsung UN55MU6300 firmware RE](https://github.com/ParkWardRR/samsung-un55mu6300-tizen-firmware-reverse-engineering) — Parent research project

## License

Blue Oak Model License 1.0.0 — see [LICENSE](LICENSE).
