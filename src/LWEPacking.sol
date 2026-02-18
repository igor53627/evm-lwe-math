// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title LWEPacking
/// @notice Pack/unpack utilities for LWE coefficient vectors.
/// @dev Supports both 12-bit (LSB-first, 21/word) and 16-bit (MSB-first, 16/word) layouts.
library LWEPacking {
    // ──────────────────────────────────────────────────────────────────────
    //  12-bit packing (LSB-first, 21 elements per uint256)
    //  Used by: lwe-jump-table (q=4096)
    // ──────────────────────────────────────────────────────────────────────

    /// @notice Packs a vector of 12-bit integers into uint256 words (LSB-first).
    /// @param input Unpacked elements (each < 4096)
    /// @return packed Array of ceil(n/21) uint256 words
    function packVector12(uint256[] memory input) internal pure returns (uint256[] memory packed) {
        uint256 n = input.length;
        uint256 packedSize = (n + 20) / 21;
        packed = new uint256[](packedSize);

        uint256 currentWord = 0;
        uint256 countInWord = 0;
        uint256 wordIndex = 0;

        for (uint256 i = 0; i < n; i++) {
            require(input[i] < 4096, "Element exceeds 12 bits");
            currentWord |= (input[i] << (countInWord * 12));
            countInWord++;

            if (countInWord == 21) {
                packed[wordIndex] = currentWord;
                wordIndex++;
                currentWord = 0;
                countInWord = 0;
            }
        }

        if (countInWord > 0) {
            packed[wordIndex] = currentWord;
        }
    }

    /// @notice Unpacks a 12-bit packed vector back into individual elements.
    /// @param packed Packed uint256 words (LSB-first, 21 per word)
    /// @param n Number of elements to unpack
    /// @return unpacked Array of n elements
    function unpackVector12(uint256[] memory packed, uint256 n)
        internal
        pure
        returns (uint256[] memory unpacked)
    {
        unpacked = new uint256[](n);
        uint256 wordIndex = 0;
        uint256 countInWord = 0;
        uint256 currentWord = packed[0];

        for (uint256 i = 0; i < n; i++) {
            unpacked[i] = (currentWord >> (countInWord * 12)) & 0xFFF;
            countInWord++;

            if (countInWord == 21) {
                wordIndex++;
                if (wordIndex < packed.length) {
                    currentWord = packed[wordIndex];
                }
                countInWord = 0;
            }
        }
    }

    // ──────────────────────────────────────────────────────────────────────
    //  16-bit packing (MSB-first, 16 elements per uint256)
    //  Used by: TLOS (q=65521)
    // ──────────────────────────────────────────────────────────────────────

    /// @notice Packs a vector of 16-bit integers into uint256 words (MSB-first).
    /// @param input Unpacked elements (each < 65536)
    /// @param q Modulus for validation (elements must be < q)
    /// @return packed Array of ceil(n/16) uint256 words
    function packVector16(uint256[] memory input, uint256 q)
        internal
        pure
        returns (uint256[] memory packed)
    {
        uint256 n = input.length;
        uint256 packedSize = (n + 15) / 16;
        packed = new uint256[](packedSize);

        for (uint256 w = 0; w < packedSize; w++) {
            uint256 word = 0;
            for (uint256 k = 0; k < 16; k++) {
                uint256 idx = w * 16 + k;
                if (idx >= n) break;
                require(input[idx] < q, "Element exceeds modulus");
                uint256 shift = (15 - k) * 16;
                word |= (input[idx] << shift);
            }
            packed[w] = word;
        }
    }

    /// @notice Unpacks a 16-bit packed vector back into individual elements.
    /// @param packed Packed uint256 words (MSB-first, 16 per word)
    /// @param n Number of elements to unpack
    /// @return unpacked Array of n elements
    function unpackVector16(uint256[] memory packed, uint256 n)
        internal
        pure
        returns (uint256[] memory unpacked)
    {
        unpacked = new uint256[](n);

        for (uint256 i = 0; i < n; i++) {
            uint256 wordIdx = i / 16;
            uint256 posInWord = i % 16;
            uint256 shift = (15 - posInWord) * 16;
            unpacked[i] = (packed[wordIdx] >> shift) & 0xFFFF;
        }
    }
}
