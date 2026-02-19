// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title LWEPacking
/// @notice Pack/unpack utilities for LWE coefficient vectors.
/// @dev Supports both 12-bit (LSB-first, 21/word) and 16-bit (MSB-first, 16/word) layouts.
library LWEPacking {
    uint256 internal constant BIT_WIDTH_12 = 12;
    uint256 internal constant ELEMENTS_PER_WORD_12 = 21;
    uint256 internal constant MASK_12 = 0xFFF;
    uint256 internal constant MAX_12 = 4096;

    uint256 internal constant BIT_WIDTH_16 = 16;
    uint256 internal constant ELEMENTS_PER_WORD_16 = 16;
    uint256 internal constant MASK_16 = 0xFFFF;

    // ──────────────────────────────────────────────────────────────────────
    //  12-bit packing (LSB-first, 21 elements per uint256)
    //  Used by: lwe-jump-table (q=4096)
    // ──────────────────────────────────────────────────────────────────────

    /// @notice Packs a vector of 12-bit integers into uint256 words (LSB-first).
    /// @param input Unpacked elements (each < 4096)
    /// @return packed Array of ceil(n/21) uint256 words
    function packVector12(uint256[] memory input) internal pure returns (uint256[] memory packed) {
        uint256 n = input.length;
        uint256 packedSize = (n + ELEMENTS_PER_WORD_12 - 1) / ELEMENTS_PER_WORD_12;
        packed = new uint256[](packedSize);

        uint256 currentWord = 0;
        uint256 countInWord = 0;
        uint256 wordIndex = 0;

        for (uint256 i = 0; i < n; i++) {
            require(input[i] < MAX_12, "Element exceeds 12 bits");
            currentWord |= (input[i] << (countInWord * BIT_WIDTH_12));
            countInWord++;

            if (countInWord == ELEMENTS_PER_WORD_12) {
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
        if (n == 0) return unpacked;
        require(packed.length >= (n + ELEMENTS_PER_WORD_12 - 1) / ELEMENTS_PER_WORD_12, "packed array too small for n");
        uint256 wordIndex = 0;
        uint256 countInWord = 0;
        uint256 currentWord = packed[0];

        for (uint256 i = 0; i < n; i++) {
            unpacked[i] = (currentWord >> (countInWord * BIT_WIDTH_12)) & MASK_12;
            countInWord++;

            if (countInWord == ELEMENTS_PER_WORD_12) {
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
        require(q > 0 && q <= 65536, "q must fit in 16-bit lanes");
        uint256 n = input.length;
        uint256 packedSize = (n + ELEMENTS_PER_WORD_16 - 1) / ELEMENTS_PER_WORD_16;
        packed = new uint256[](packedSize);

        for (uint256 w = 0; w < packedSize; w++) {
            uint256 word = 0;
            for (uint256 k = 0; k < ELEMENTS_PER_WORD_16; k++) {
                uint256 idx = w * ELEMENTS_PER_WORD_16 + k;
                if (idx >= n) break;
                require(input[idx] < q, "Element exceeds modulus");
                uint256 shift = (ELEMENTS_PER_WORD_16 - 1 - k) * BIT_WIDTH_16;
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
            uint256 wordIdx = i / ELEMENTS_PER_WORD_16;
            uint256 posInWord = i % ELEMENTS_PER_WORD_16;
            uint256 shift = (ELEMENTS_PER_WORD_16 - 1 - posInWord) * BIT_WIDTH_16;
            unpacked[i] = (packed[wordIdx] >> shift) & MASK_16;
        }
    }
}
