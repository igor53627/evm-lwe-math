# evm-lwe-math

Gas-optimized LWE (Learning With Errors) primitives for on-chain lattice cryptography.

## What it provides

| Module | Purpose |
|--------|---------|
| `LibLWE` | Inner-product computation, key expansion, decrypt helpers, threshold/sector decode |
| `LWEPacking` | Pack/unpack utilities for 12-bit and 16-bit coefficient vectors |
| `LWETestUtils` | Key generation, noise sampling, encrypt/decrypt (test/dev only) |

## Supported parameter sets

| Parameter | TLOS-style | Jump-table-style |
|-----------|-----------|-----------------|
| Modulus q | 65521 (prime) | 4096 (2^12) |
| Dimension n | 384 | 768 |
| Bit width | 16 | 12 |
| Elements/word | 16 (MSB-first) | 21 (LSB-first) |
| Packed words | 24 | 37 |
| Mod reduction | `mod q` | `& 0xFFF` |

Both parameter sets are supported through parameterized functions.

## Core API

### Inner products

```solidity
// 16-bit packed (prime modulus)
LibLWE.innerProduct16(a, s, numWords, q)

// 16-bit with seed-derived A-vector (no storage needed)
LibLWE.innerProductSeedDerived(domain, seed, idx0, idx1, s, numWords, q)

// 12-bit packed (power-of-2 modulus, bitmask)
LibLWE.innerProduct12(a, s, numWords, qMask)
```

### Key expansion

```solidity
// Expand keySeed into packed secret vector (16-bit MSB-first)
uint256[] memory s = LibLWE.expandKey(keySeed, 24, 65521);
```

### Decryption

```solidity
// Prime modulus: (b - innerProd) mod q
LibLWE.decryptPrime(b, innerProd, q)

// Power-of-2 modulus: (b - innerProd) & mask
LibLWE.decryptPow2(b, innerProd, qMask)
```

### Decode

```solidity
// 1-bit threshold decode (TLOS-style)
LibLWE.thresholdDecode(diff, threshold)

// 4-sector decode (jump-table-style)
LibLWE.sectorDecode(diff, q)
```

### Packing

```solidity
// 12-bit (21 elements/word, LSB-first)
uint256[] memory packed = LWEPacking.packVector12(input);
uint256[] memory unpacked = LWEPacking.unpackVector12(packed, n);

// 16-bit (16 elements/word, MSB-first)
uint256[] memory packed = LWEPacking.packVector16(input, q);
uint256[] memory unpacked = LWEPacking.unpackVector16(packed, n);
```

## Usage as dependency

Add as a git submodule:

```bash
forge install <org>/evm-lwe-math
```

Then import:

```solidity
import {LibLWE} from "evm-lwe-math/src/LibLWE.sol";
import {LWEPacking} from "evm-lwe-math/src/LWEPacking.sol";
```

## Build & test

```bash
forge build
forge test -vv
```

## Gas benchmarks

| Operation | Parameters | Gas |
|-----------|-----------|-----|
| `innerProduct16` (24 words) | n=384, q=65521 | ~21K |
| `innerProduct12` (37 words) | n=768, q=4096 | ~52K |
| `innerProductSeedDerived` (24 words) | n=384, q=65521 | ~244K |
| `expandKey` (24 words) | n=384, q=65521 | ~95K |
| `packVector12` (768 elements) | 12-bit | ~1.7M |
| `packVector16` (384 elements) | 16-bit | ~1.2M |

## Related projects

- [tlos](https://github.com/igor53627/tlos) - Topology-Lattice Obfuscation for Smart Contracts
- [lwe-jump-table](https://github.com/igor53627/lwe-jump-table) - LWE-based control flow flattening
- [evm-mhf](https://github.com/igor53627/evm-mhf) - Memory-hard function for EVM

## Audit

- [Nethermind AuditAgent scan #36](audits/audit-agent-nethermind-2026-02-18.pdf) (2026-02-18) — 5 Low, 0 High/Medium. All findings addressed in [PR #1](https://github.com/igor53627/evm-lwe-math/pull/1).

## License

MIT
