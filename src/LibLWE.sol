// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title LibLWE
/// @notice Gas-optimized LWE (Learning With Errors) primitives for on-chain lattice cryptography.
/// @dev Supports both prime moduli (e.g. q=65521) and power-of-2 moduli (e.g. q=4096).
///      All inner-product functions use packed representations for gas efficiency.
library LibLWE {
    // ──────────────────────────────────────────────────────────────────────
    //  16-bit packed inner product (prime modulus)
    //  Layout: 16 elements per uint256, MSB-first (bits 240..255 = element 0)
    //  Used by: TLOS (n=384, q=65521, 24 words)
    // ──────────────────────────────────────────────────────────────────────

    /// @notice Computes ⟨a, s⟩ mod q for 16-bit packed vectors.
    /// @param a Packed A-vector (16 elements per word, MSB-first)
    /// @param s Packed secret vector (same layout)
    /// @param numWords Number of uint256 words (n = numWords * 16)
    /// @param q Prime modulus
    /// @return result The inner product mod q
    function innerProduct16(
        uint256[] memory a,
        uint256[] memory s,
        uint256 numWords,
        uint256 q
    ) internal pure returns (uint256 result) {
        assembly {
            let aPtr := add(a, 32)
            let sPtr := add(s, 32)
            let acc := 0

            for { let w := 0 } lt(w, numWords) { w := add(w, 1) } {
                let aWord := mload(add(aPtr, mul(w, 32)))
                let sWord := mload(add(sPtr, mul(w, 32)))

                // Unroll 16 elements per word (MSB-first, 16-bit)
                acc := add(acc, mul(and(shr(240, aWord), 0xFFFF), and(shr(240, sWord), 0xFFFF)))
                acc := add(acc, mul(and(shr(224, aWord), 0xFFFF), and(shr(224, sWord), 0xFFFF)))
                acc := add(acc, mul(and(shr(208, aWord), 0xFFFF), and(shr(208, sWord), 0xFFFF)))
                acc := add(acc, mul(and(shr(192, aWord), 0xFFFF), and(shr(192, sWord), 0xFFFF)))
                acc := add(acc, mul(and(shr(176, aWord), 0xFFFF), and(shr(176, sWord), 0xFFFF)))
                acc := add(acc, mul(and(shr(160, aWord), 0xFFFF), and(shr(160, sWord), 0xFFFF)))
                acc := add(acc, mul(and(shr(144, aWord), 0xFFFF), and(shr(144, sWord), 0xFFFF)))
                acc := add(acc, mul(and(shr(128, aWord), 0xFFFF), and(shr(128, sWord), 0xFFFF)))
                acc := add(acc, mul(and(shr(112, aWord), 0xFFFF), and(shr(112, sWord), 0xFFFF)))
                acc := add(acc, mul(and(shr( 96, aWord), 0xFFFF), and(shr( 96, sWord), 0xFFFF)))
                acc := add(acc, mul(and(shr( 80, aWord), 0xFFFF), and(shr( 80, sWord), 0xFFFF)))
                acc := add(acc, mul(and(shr( 64, aWord), 0xFFFF), and(shr( 64, sWord), 0xFFFF)))
                acc := add(acc, mul(and(shr( 48, aWord), 0xFFFF), and(shr( 48, sWord), 0xFFFF)))
                acc := add(acc, mul(and(shr( 32, aWord), 0xFFFF), and(shr( 32, sWord), 0xFFFF)))
                acc := add(acc, mul(and(shr( 16, aWord), 0xFFFF), and(shr( 16, sWord), 0xFFFF)))
                acc := add(acc, mul(and(       aWord, 0xFFFF), and(       sWord, 0xFFFF)))
            }

            result := mod(acc, q)
        }
    }

    // ──────────────────────────────────────────────────────────────────────
    //  16-bit seed-derived inner product (prime modulus)
    //  A-vector is derived on-the-fly via keccak256(domain || seed || idx...)
    //  Used by: TLOS gate evaluation
    // ──────────────────────────────────────────────────────────────────────

    /// @notice Computes ⟨a, s⟩ mod q where a is derived from a seed via keccak256.
    /// @param domain Domain separator (e.g. keccak256("TLOS-LWE-A-v1"))
    /// @param seed Circuit/instance seed
    /// @param idx0 First index (e.g. gate index)
    /// @param idx1 Second index (e.g. truth-table index)
    /// @param s Packed secret vector (16 elements per word, MSB-first)
    /// @param numWords Number of uint256 words in s
    /// @param q Prime modulus
    /// @return result The inner product mod q
    function innerProductSeedDerived(
        bytes32 domain,
        bytes32 seed,
        uint256 idx0,
        uint256 idx1,
        uint256[] memory s,
        uint256 numWords,
        uint256 q
    ) internal pure returns (uint256 result) {
        assembly {
            let sPtr := add(s, 32)
            let acc := 0
            let scratch := mload(0x40)

            mstore(scratch, domain)
            mstore(add(scratch, 32), seed)
            mstore(add(scratch, 64), idx0)
            mstore(add(scratch, 96), idx1)

            for { let w := 0 } lt(w, numWords) { w := add(w, 1) } {
                mstore(add(scratch, 128), w)
                let aWord := keccak256(scratch, 160)
                let sWord := mload(add(sPtr, mul(w, 32)))

                acc := add(acc, mul(and(shr(240, aWord), 0xFFFF), and(shr(240, sWord), 0xFFFF)))
                acc := add(acc, mul(and(shr(224, aWord), 0xFFFF), and(shr(224, sWord), 0xFFFF)))
                acc := add(acc, mul(and(shr(208, aWord), 0xFFFF), and(shr(208, sWord), 0xFFFF)))
                acc := add(acc, mul(and(shr(192, aWord), 0xFFFF), and(shr(192, sWord), 0xFFFF)))
                acc := add(acc, mul(and(shr(176, aWord), 0xFFFF), and(shr(176, sWord), 0xFFFF)))
                acc := add(acc, mul(and(shr(160, aWord), 0xFFFF), and(shr(160, sWord), 0xFFFF)))
                acc := add(acc, mul(and(shr(144, aWord), 0xFFFF), and(shr(144, sWord), 0xFFFF)))
                acc := add(acc, mul(and(shr(128, aWord), 0xFFFF), and(shr(128, sWord), 0xFFFF)))
                acc := add(acc, mul(and(shr(112, aWord), 0xFFFF), and(shr(112, sWord), 0xFFFF)))
                acc := add(acc, mul(and(shr( 96, aWord), 0xFFFF), and(shr( 96, sWord), 0xFFFF)))
                acc := add(acc, mul(and(shr( 80, aWord), 0xFFFF), and(shr( 80, sWord), 0xFFFF)))
                acc := add(acc, mul(and(shr( 64, aWord), 0xFFFF), and(shr( 64, sWord), 0xFFFF)))
                acc := add(acc, mul(and(shr( 48, aWord), 0xFFFF), and(shr( 48, sWord), 0xFFFF)))
                acc := add(acc, mul(and(shr( 32, aWord), 0xFFFF), and(shr( 32, sWord), 0xFFFF)))
                acc := add(acc, mul(and(shr( 16, aWord), 0xFFFF), and(shr( 16, sWord), 0xFFFF)))
                acc := add(acc, mul(and(       aWord, 0xFFFF), and(       sWord, 0xFFFF)))
            }

            result := mod(acc, q)
        }
    }

    // ──────────────────────────────────────────────────────────────────────
    //  12-bit packed inner product (power-of-2 modulus, bitmask)
    //  Layout: 21 elements per uint256, LSB-first (bits 0..11 = element 0)
    //  Used by: lwe-jump-table (n=768, q=4096, 37 words)
    // ──────────────────────────────────────────────────────────────────────

    /// @notice Computes ⟨a, s⟩ mod q for 12-bit packed vectors (q must be power of 2).
    /// @param a Packed A-vector (21 elements per word, LSB-first)
    /// @param s Packed secret vector (same layout)
    /// @param numWords Number of uint256 words (n = numWords * 21, approximately)
    /// @param qMask Bitmask for modulus (q - 1, e.g. 0xFFF for q=4096)
    /// @return result The inner product mod q
    function innerProduct12(
        uint256[] memory a,
        uint256[] memory s,
        uint256 numWords,
        uint256 qMask
    ) internal pure returns (uint256 result) {
        assembly {
            let aPtr := add(a, 32)
            let sPtr := add(s, 32)
            let acc := 0
            let mask := 0xFFF

            for { let i := 0 } lt(i, numWords) { i := add(i, 1) } {
                let w_a := mload(add(aPtr, mul(i, 32)))
                let w_s := mload(add(sPtr, mul(i, 32)))

                // Unroll 21 elements per word (LSB-first, 12-bit)
                acc := add(acc, mul(and(w_a, mask), and(w_s, mask)))
                w_a := shr(12, w_a)
                w_s := shr(12, w_s)

                acc := add(acc, mul(and(w_a, mask), and(w_s, mask)))
                w_a := shr(12, w_a)
                w_s := shr(12, w_s)

                acc := add(acc, mul(and(w_a, mask), and(w_s, mask)))
                w_a := shr(12, w_a)
                w_s := shr(12, w_s)

                acc := add(acc, mul(and(w_a, mask), and(w_s, mask)))
                w_a := shr(12, w_a)
                w_s := shr(12, w_s)

                acc := add(acc, mul(and(w_a, mask), and(w_s, mask)))
                w_a := shr(12, w_a)
                w_s := shr(12, w_s)

                acc := add(acc, mul(and(w_a, mask), and(w_s, mask)))
                w_a := shr(12, w_a)
                w_s := shr(12, w_s)

                acc := add(acc, mul(and(w_a, mask), and(w_s, mask)))
                w_a := shr(12, w_a)
                w_s := shr(12, w_s)

                acc := add(acc, mul(and(w_a, mask), and(w_s, mask)))
                w_a := shr(12, w_a)
                w_s := shr(12, w_s)

                acc := add(acc, mul(and(w_a, mask), and(w_s, mask)))
                w_a := shr(12, w_a)
                w_s := shr(12, w_s)

                acc := add(acc, mul(and(w_a, mask), and(w_s, mask)))
                w_a := shr(12, w_a)
                w_s := shr(12, w_s)

                acc := add(acc, mul(and(w_a, mask), and(w_s, mask)))
                w_a := shr(12, w_a)
                w_s := shr(12, w_s)

                acc := add(acc, mul(and(w_a, mask), and(w_s, mask)))
                w_a := shr(12, w_a)
                w_s := shr(12, w_s)

                acc := add(acc, mul(and(w_a, mask), and(w_s, mask)))
                w_a := shr(12, w_a)
                w_s := shr(12, w_s)

                acc := add(acc, mul(and(w_a, mask), and(w_s, mask)))
                w_a := shr(12, w_a)
                w_s := shr(12, w_s)

                acc := add(acc, mul(and(w_a, mask), and(w_s, mask)))
                w_a := shr(12, w_a)
                w_s := shr(12, w_s)

                acc := add(acc, mul(and(w_a, mask), and(w_s, mask)))
                w_a := shr(12, w_a)
                w_s := shr(12, w_s)

                acc := add(acc, mul(and(w_a, mask), and(w_s, mask)))
                w_a := shr(12, w_a)
                w_s := shr(12, w_s)

                acc := add(acc, mul(and(w_a, mask), and(w_s, mask)))
                w_a := shr(12, w_a)
                w_s := shr(12, w_s)

                acc := add(acc, mul(and(w_a, mask), and(w_s, mask)))
                w_a := shr(12, w_a)
                w_s := shr(12, w_s)

                acc := add(acc, mul(and(w_a, mask), and(w_s, mask)))
                w_a := shr(12, w_a)
                w_s := shr(12, w_s)

                acc := add(acc, mul(and(w_a, mask), and(w_s, mask)))
            }

            result := and(acc, qMask)
        }
    }

    // ──────────────────────────────────────────────────────────────────────
    //  Key expansion
    // ──────────────────────────────────────────────────────────────────────

    /// @notice Expands a key seed into a packed secret vector (16-bit, MSB-first).
    /// @param keySeed The seed to expand (e.g. keccak256(domain || mhtOutput))
    /// @param numWords Number of output words (n = numWords * 16)
    /// @param q Modulus for element reduction
    /// @return s Packed secret vector
    function expandKey(bytes32 keySeed, uint256 numWords, uint256 q)
        internal
        pure
        returns (uint256[] memory s)
    {
        s = new uint256[](numWords);
        assembly {
            let sPtr := add(s, 32)
            for { let j := 0 } lt(j, numWords) { j := add(j, 1) } {
                mstore(0x00, keySeed)
                mstore(0x20, j)
                let hVal := keccak256(0x00, 0x40)

                let sVal := 0
                for { let i := 0 } lt(i, 16) { i := add(i, 1) } {
                    let shift := mul(sub(15, i), 16)
                    sVal := or(sVal, shl(shift, mod(and(shr(shift, hVal), 0xFFFF), q)))
                }
                mstore(add(sPtr, mul(j, 32)), sVal)
            }
        }
    }

    // ──────────────────────────────────────────────────────────────────────
    //  Decryption helpers
    // ──────────────────────────────────────────────────────────────────────

    /// @notice Computes (b - innerProd) mod q for prime modulus.
    function decryptPrime(uint256 b, uint256 innerProd, uint256 q)
        internal
        pure
        returns (uint256)
    {
        return (b + q - (innerProd % q)) % q;
    }

    /// @notice Computes (b - innerProd) mod q for power-of-2 modulus (bitmask).
    function decryptPow2(uint256 b, uint256 innerProd, uint256 qMask)
        internal
        pure
        returns (uint256 result)
    {
        // Unchecked to allow intentional underflow wrap-around
        assembly {
            result := and(sub(b, innerProd), qMask)
        }
    }

    /// @notice Threshold decode: returns 1 if diff is in the "true" band.
    /// @dev For q/4 threshold: true band is (q/4, 3q/4).
    function thresholdDecode(uint256 diff, uint256 threshold)
        internal
        pure
        returns (uint256 bit)
    {
        assembly {
            bit := and(gt(diff, threshold), lt(diff, mul(3, threshold)))
        }
    }

    /// @notice 4-sector decode for multi-way dispatch.
    /// @dev Sector 0: [0, q/4), Sector 1: [q/4, q/2), Sector 2: [q/2, 3q/4), Sector 3: [3q/4, q)
    function sectorDecode(uint256 diff, uint256 q)
        internal
        pure
        returns (uint256 sector)
    {
        uint256 quarter = q / 4;
        if (diff < quarter) return 0;
        if (diff < 2 * quarter) return 1;
        if (diff < 3 * quarter) return 2;
        return 3;
    }
}
