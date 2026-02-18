// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title LWETestUtils
/// @notice Test/development utilities for LWE operations: key generation, noise sampling, encrypt/decrypt.
/// @dev NOT intended for production use — these are reference implementations for testing correctness.
library LWETestUtils {
    struct RNG {
        uint256 seed;
    }

    function initRNG(uint256 seed) internal pure returns (RNG memory) {
        return RNG({seed: seed});
    }

    function next(RNG memory rng) internal pure returns (uint256) {
        rng.seed = uint256(keccak256(abi.encodePacked(rng.seed)));
        return rng.seed;
    }

    /// @notice Generates a random secret vector s in [0, q)^n.
    function generateSecret(RNG memory rng, uint256 n, uint256 q)
        internal
        pure
        returns (uint256[] memory s)
    {
        s = new uint256[](n);
        for (uint256 i = 0; i < n; i++) {
            s[i] = next(rng) % q;
        }
    }

    /// @notice Samples centered binomial noise with parameter k.
    /// @dev Returns value in [-k/2, k/2], mapped to [0, q).
    function sampleNoise(RNG memory rng, uint256 k, uint256 q)
        internal
        pure
        returns (uint256)
    {
        uint256 rand = next(rng);
        uint256 halfK = k / 2;
        uint256 mask = (1 << halfK) - 1;

        uint256 a = rand & mask;
        uint256 b = (rand >> halfK) & mask;

        uint256 countA = _popcount(a);
        uint256 countB = _popcount(b);

        if (countA >= countB) {
            return (countA - countB) % q;
        } else {
            return (q - (countB - countA) % q) % q;
        }
    }

    /// @notice Generates an LWE sample: b = ⟨a, s⟩ + e + m (mod q).
    /// @param s Secret vector (unpacked)
    /// @param m Message to encode
    /// @param noiseK Noise parameter for centered binomial
    /// @param q Modulus
    /// @return a Random public vector
    /// @return b LWE ciphertext scalar
    function encrypt(
        RNG memory rng,
        uint256[] memory s,
        uint256 m,
        uint256 noiseK,
        uint256 q
    ) internal pure returns (uint256[] memory a, uint256 b) {
        uint256 n = s.length;
        a = new uint256[](n);
        uint256 innerProd = 0;

        for (uint256 i = 0; i < n; i++) {
            a[i] = next(rng) % q;
            innerProd += a[i] * s[i];
        }

        uint256 noise = sampleNoise(rng, noiseK, q);
        b = (innerProd % q + noise + m) % q;
    }

    /// @notice Decrypts an LWE sample: mApprox = (b - ⟨a, s⟩) mod q.
    function decrypt(
        uint256[] memory a,
        uint256 b,
        uint256[] memory s,
        uint256 q
    ) internal pure returns (uint256 mApprox) {
        uint256 innerProd = 0;
        uint256 n = s.length;

        for (uint256 i = 0; i < n; i++) {
            innerProd += a[i] * s[i];
        }
        innerProd = innerProd % q;

        if (b >= innerProd) {
            mApprox = (b - innerProd) % q;
        } else {
            mApprox = (b + q - innerProd) % q;
        }
    }

    function _popcount(uint256 x) private pure returns (uint256 count) {
        while (x != 0) {
            count += x & 1;
            x >>= 1;
        }
    }
}
