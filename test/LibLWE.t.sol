// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {LibLWE} from "../src/LibLWE.sol";
import {LWEPacking} from "../src/LWEPacking.sol";
import {LWETestUtils} from "../src/LWETestUtils.sol";

/// @dev Wrapper to test library reverts via external calls.
contract LibLWEHarness {
    function innerProduct16(uint256[] memory a, uint256[] memory s, uint256 numWords, uint256 q)
        external pure returns (uint256) { return LibLWE.innerProduct16(a, s, numWords, q); }
    function innerProduct12(uint256[] memory a, uint256[] memory s, uint256 numWords, uint256 qMask)
        external pure returns (uint256) { return LibLWE.innerProduct12(a, s, numWords, qMask); }
    function innerProductSeedDerived(bytes32 d, bytes32 seed, uint256 i0, uint256 i1, uint256[] memory s, uint256 nw, uint256 q)
        external pure returns (uint256) { return LibLWE.innerProductSeedDerived(d, seed, i0, i1, s, nw, q); }
    function expandKey(bytes32 keySeed, uint256 numWords, uint256 q)
        external pure returns (uint256[] memory) { return LibLWE.expandKey(keySeed, numWords, q); }
    function packVector16(uint256[] memory input, uint256 q)
        external pure returns (uint256[] memory) { return LWEPacking.packVector16(input, q); }
    function unpackVector12(uint256[] memory packed, uint256 n)
        external pure returns (uint256[] memory) { return LWEPacking.unpackVector12(packed, n); }
}

contract LibLWETest is Test {
    LibLWEHarness harness;

    function setUp() public {
        harness = new LibLWEHarness();
    }

    // ──────────────────────────────────────────────────────────────────
    //  16-bit inner product tests (TLOS-style, q=65521)
    // ──────────────────────────────────────────────────────────────────

    uint256 constant Q_PRIME = 65521;
    uint256 constant N_TLOS = 384; // 24 words * 16 elements

    function test_innerProduct16_zero() public pure {
        uint256[] memory a = new uint256[](24);
        uint256[] memory s = new uint256[](24);
        uint256 result = LibLWE.innerProduct16(a, s, 24, Q_PRIME);
        assertEq(result, 0);
    }

    function test_innerProduct16_identity() public pure {
        // Single element: a[0] = 1 in MSB position, s[0] = 42 in MSB position
        uint256[] memory a = new uint256[](1);
        uint256[] memory s = new uint256[](1);
        a[0] = uint256(1) << 240; // element 0 = 1
        s[0] = uint256(42) << 240; // element 0 = 42
        uint256 result = LibLWE.innerProduct16(a, s, 1, Q_PRIME);
        assertEq(result, 42);
    }

    function test_innerProduct16_modReduction() public pure {
        // Two elements that multiply to > q
        uint256[] memory a = new uint256[](1);
        uint256[] memory s = new uint256[](1);
        // element 0: a=65520 (q-1), s=2 => product = 131040, mod 65521 = 131040 - 65521 = 65519
        a[0] = uint256(65520) << 240;
        s[0] = uint256(2) << 240;
        uint256 result = LibLWE.innerProduct16(a, s, 1, Q_PRIME);
        assertEq(result, (65520 * 2) % Q_PRIME);
    }

    function test_innerProduct16_multiWord() public pure {
        uint256[] memory a = new uint256[](2);
        uint256[] memory s = new uint256[](2);

        // Word 0: element 0 = 3
        a[0] = uint256(3) << 240;
        s[0] = uint256(7) << 240;
        // Word 1: element 0 = 5
        a[1] = uint256(5) << 240;
        s[1] = uint256(11) << 240;
        // Expected: (3*7 + 5*11) % q = (21 + 55) % 65521 = 76
        uint256 result = LibLWE.innerProduct16(a, s, 2, Q_PRIME);
        assertEq(result, 76);
    }

    function test_innerProduct16_allElements() public pure {
        // Fill one word with all 16 elements = 1, secret all = 1
        uint256[] memory a = new uint256[](1);
        uint256[] memory s = new uint256[](1);
        uint256 word = 0;
        for (uint256 i = 0; i < 16; i++) {
            word |= uint256(1) << ((15 - i) * 16);
        }
        a[0] = word;
        s[0] = word;
        // 16 * (1*1) = 16
        uint256 result = LibLWE.innerProduct16(a, s, 1, Q_PRIME);
        assertEq(result, 16);
    }

    // ──────────────────────────────────────────────────────────────────
    //  Seed-derived inner product tests
    // ──────────────────────────────────────────────────────────────────

    function test_innerProductSeedDerived_deterministic() public pure {
        bytes32 domain = keccak256("TEST-DOMAIN");
        bytes32 seed = keccak256("test-seed");
        uint256[] memory s = new uint256[](1);
        s[0] = uint256(1) << 240; // element 0 = 1

        uint256 r1 = LibLWE.innerProductSeedDerived(domain, seed, 0, 0, s, 1, Q_PRIME);
        uint256 r2 = LibLWE.innerProductSeedDerived(domain, seed, 0, 0, s, 1, Q_PRIME);
        assertEq(r1, r2);
    }

    function test_innerProductSeedDerived_differentIndices() public pure {
        bytes32 domain = keccak256("TEST-DOMAIN");
        bytes32 seed = keccak256("test-seed");
        uint256[] memory s = new uint256[](24);
        // Fill s with all 1s
        for (uint256 w = 0; w < 24; w++) {
            uint256 word = 0;
            for (uint256 i = 0; i < 16; i++) {
                word |= uint256(1) << ((15 - i) * 16);
            }
            s[w] = word;
        }

        uint256 r1 = LibLWE.innerProductSeedDerived(domain, seed, 0, 0, s, 24, Q_PRIME);
        uint256 r2 = LibLWE.innerProductSeedDerived(domain, seed, 1, 0, s, 24, Q_PRIME);
        assertTrue(r1 != r2, "Different gate indices should produce different results");
    }

    // ──────────────────────────────────────────────────────────────────
    //  12-bit inner product tests (jump-table-style, q=4096)
    // ──────────────────────────────────────────────────────────────────

    uint256 constant Q_POW2 = 4096;
    uint256 constant Q_MASK = 0xFFF;

    function test_innerProduct12_zero() public pure {
        uint256[] memory a = new uint256[](37);
        uint256[] memory s = new uint256[](37);
        uint256 result = LibLWE.innerProduct12(a, s, 37, Q_MASK);
        assertEq(result, 0);
    }

    function test_innerProduct12_identity() public pure {
        // element 0 (LSB): a=1, s=42
        uint256[] memory a = new uint256[](1);
        uint256[] memory s = new uint256[](1);
        a[0] = 1; // element 0 at bits 0..11
        s[0] = 42;
        uint256 result = LibLWE.innerProduct12(a, s, 1, Q_MASK);
        assertEq(result, 42);
    }

    function test_innerProduct12_bitmaskModulo() public pure {
        // 4095 * 2 = 8190 & 0xFFF = 4094
        uint256[] memory a = new uint256[](1);
        uint256[] memory s = new uint256[](1);
        a[0] = 4095;
        s[0] = 2;
        uint256 result = LibLWE.innerProduct12(a, s, 1, Q_MASK);
        assertEq(result, (4095 * 2) & Q_MASK);
    }

    function test_innerProduct12_multipleElements() public pure {
        // Two elements in one word: elem0=3, elem1=5
        uint256[] memory a = new uint256[](1);
        uint256[] memory s = new uint256[](1);
        a[0] = 3 | (5 << 12); // elem0=3, elem1=5
        s[0] = 7 | (11 << 12); // elem0=7, elem1=11
        // Expected: (3*7 + 5*11) & 0xFFF = 76
        uint256 result = LibLWE.innerProduct12(a, s, 1, Q_MASK);
        assertEq(result, 76 & Q_MASK);
    }

    // ──────────────────────────────────────────────────────────────────
    //  Key expansion tests
    // ──────────────────────────────────────────────────────────────────

    function test_expandKey_deterministic() public pure {
        bytes32 seed = keccak256("test-key-seed");
        uint256[] memory s1 = LibLWE.expandKey(seed, 24, Q_PRIME);
        uint256[] memory s2 = LibLWE.expandKey(seed, 24, Q_PRIME);
        assertEq(s1.length, 24);
        for (uint256 i = 0; i < 24; i++) {
            assertEq(s1[i], s2[i]);
        }
    }

    function test_expandKey_elementsInRange() public pure {
        bytes32 seed = keccak256("range-test");
        uint256[] memory s = LibLWE.expandKey(seed, 24, Q_PRIME);

        for (uint256 w = 0; w < 24; w++) {
            for (uint256 k = 0; k < 16; k++) {
                uint256 shift = (15 - k) * 16;
                uint256 elem = (s[w] >> shift) & 0xFFFF;
                assertTrue(elem < Q_PRIME, "Element must be < q");
            }
        }
    }

    function test_expandKey_differentSeeds() public pure {
        uint256[] memory s1 = LibLWE.expandKey(keccak256("seed-a"), 24, Q_PRIME);
        uint256[] memory s2 = LibLWE.expandKey(keccak256("seed-b"), 24, Q_PRIME);
        bool anyDifferent = false;
        for (uint256 i = 0; i < 24; i++) {
            if (s1[i] != s2[i]) {
                anyDifferent = true;
                break;
            }
        }
        assertTrue(anyDifferent, "Different seeds must produce different keys");
    }

    // ──────────────────────────────────────────────────────────────────
    //  Decrypt tests
    // ──────────────────────────────────────────────────────────────────

    function test_decryptPrime() public pure {
        // b=100, innerProd=30, q=65521 => (100 + 65521 - 30) % 65521 = 70
        assertEq(LibLWE.decryptPrime(100, 30, Q_PRIME), 70);
    }

    function test_decryptPrime_wrapAround() public pure {
        // b=10, innerProd=65520 => (10 + 65521 - 65520) % 65521 = 11
        assertEq(LibLWE.decryptPrime(10, 65520, Q_PRIME), 11);
    }

    function test_decryptPow2() public pure {
        // b=100, innerProd=30 => (100 - 30) & 0xFFF = 70
        assertEq(LibLWE.decryptPow2(100, 30, Q_MASK), 70);
    }

    function test_decryptPow2_wrapAround() public pure {
        // b=10, innerProd=4090 => (10 - 4090) & 0xFFF = underflow wraps
        uint256 expected = (10 + Q_POW2 - 4090) % Q_POW2;
        assertEq(LibLWE.decryptPow2(10, 4090, Q_MASK), expected);
    }

    // ──────────────────────────────────────────────────────────────────
    //  Threshold & sector decode
    // ──────────────────────────────────────────────────────────────────

    function test_thresholdDecode() public pure {
        uint256 threshold = Q_PRIME / 4;
        // Below threshold => 0
        assertEq(LibLWE.thresholdDecode(0, threshold), 0);
        assertEq(LibLWE.thresholdDecode(threshold, threshold), 0);
        // In true band => 1
        assertEq(LibLWE.thresholdDecode(threshold + 1, threshold), 1);
        assertEq(LibLWE.thresholdDecode(2 * threshold, threshold), 1);
        // Above 3*threshold => 0
        assertEq(LibLWE.thresholdDecode(3 * threshold, threshold), 0);
    }

    function test_sectorDecode() public pure {
        assertEq(LibLWE.sectorDecode(0, Q_POW2), 0);
        assertEq(LibLWE.sectorDecode(1023, Q_POW2), 0);
        assertEq(LibLWE.sectorDecode(1024, Q_POW2), 1);
        assertEq(LibLWE.sectorDecode(2047, Q_POW2), 1);
        assertEq(LibLWE.sectorDecode(2048, Q_POW2), 2);
        assertEq(LibLWE.sectorDecode(3071, Q_POW2), 2);
        assertEq(LibLWE.sectorDecode(3072, Q_POW2), 3);
        assertEq(LibLWE.sectorDecode(4095, Q_POW2), 3);
    }

    // ──────────────────────────────────────────────────────────────────
    //  End-to-end encrypt/decrypt roundtrip
    // ──────────────────────────────────────────────────────────────────

    function test_e2e_encryptDecrypt_sector0() public pure {
        _testEncryptDecryptRoundtrip(0, 0); // message = 0 (sector 0)
    }

    function test_e2e_encryptDecrypt_sector1() public pure {
        _testEncryptDecryptRoundtrip(Q_POW2 / 4, 1); // message = q/4 (sector 1)
    }

    function test_e2e_encryptDecrypt_sector2() public pure {
        _testEncryptDecryptRoundtrip(Q_POW2 / 2, 2); // message = q/2 (sector 2)
    }

    function test_e2e_encryptDecrypt_sector3() public pure {
        _testEncryptDecryptRoundtrip(3 * Q_POW2 / 4, 3); // message = 3q/4 (sector 3)
    }

    function _testEncryptDecryptRoundtrip(uint256 message, uint256 expectedSector) internal pure {
        uint256 n = 32; // small dimension for test speed
        uint256 q = Q_POW2;

        LWETestUtils.RNG memory rng = LWETestUtils.initRNG(42 + message);
        uint256[] memory s = LWETestUtils.generateSecret(rng, n, q);
        (uint256[] memory a, uint256 b) = LWETestUtils.encrypt(rng, s, message, 16, q);
        uint256 mApprox = LWETestUtils.decrypt(a, b, s, q);
        uint256 sector = LibLWE.sectorDecode(mApprox, q);
        assertEq(sector, expectedSector);
    }

    // ──────────────────────────────────────────────────────────────────
    //  Packing roundtrip tests
    // ──────────────────────────────────────────────────────────────────

    function test_packing12_roundtrip() public pure {
        uint256[] memory original = new uint256[](768);
        for (uint256 i = 0; i < 768; i++) {
            original[i] = (i * 37 + 13) % 4096;
        }

        uint256[] memory packed = LWEPacking.packVector12(original);
        assertEq(packed.length, 37); // ceil(768/21)

        uint256[] memory unpacked = LWEPacking.unpackVector12(packed, 768);
        for (uint256 i = 0; i < 768; i++) {
            assertEq(unpacked[i], original[i], "12-bit roundtrip mismatch");
        }
    }

    function test_packing16_roundtrip() public pure {
        uint256[] memory original = new uint256[](384);
        for (uint256 i = 0; i < 384; i++) {
            original[i] = (i * 173 + 7) % Q_PRIME;
        }

        uint256[] memory packed = LWEPacking.packVector16(original, Q_PRIME);
        assertEq(packed.length, 24); // ceil(384/16)

        uint256[] memory unpacked = LWEPacking.unpackVector16(packed, 384);
        for (uint256 i = 0; i < 384; i++) {
            assertEq(unpacked[i], original[i], "16-bit roundtrip mismatch");
        }
    }

    // ──────────────────────────────────────────────────────────────────
    //  Cross-validation: packed inner product matches unpacked
    // ──────────────────────────────────────────────────────────────────

    function test_innerProduct16_matchesNaive() public pure {
        uint256 n = 32;
        uint256[] memory aRaw = new uint256[](n);
        uint256[] memory sRaw = new uint256[](n);

        for (uint256 i = 0; i < n; i++) {
            aRaw[i] = uint256(keccak256(abi.encodePacked("a", i))) % Q_PRIME;
            sRaw[i] = uint256(keccak256(abi.encodePacked("s", i))) % Q_PRIME;
        }

        // Compute naive inner product
        uint256 naiveResult = 0;
        for (uint256 i = 0; i < n; i++) {
            naiveResult += aRaw[i] * sRaw[i];
        }
        naiveResult = naiveResult % Q_PRIME;

        // Pack and compute via library
        uint256[] memory aPacked = LWEPacking.packVector16(aRaw, Q_PRIME);
        uint256[] memory sPacked = LWEPacking.packVector16(sRaw, Q_PRIME);
        uint256 libResult = LibLWE.innerProduct16(aPacked, sPacked, aPacked.length, Q_PRIME);

        assertEq(libResult, naiveResult, "Packed inner product must match naive");
    }

    function test_innerProduct12_matchesNaive() public pure {
        uint256 n = 42; // 2 words of 21
        uint256[] memory aRaw = new uint256[](n);
        uint256[] memory sRaw = new uint256[](n);

        for (uint256 i = 0; i < n; i++) {
            aRaw[i] = uint256(keccak256(abi.encodePacked("a12", i))) % Q_POW2;
            sRaw[i] = uint256(keccak256(abi.encodePacked("s12", i))) % Q_POW2;
        }

        // Compute naive inner product
        uint256 naiveResult = 0;
        for (uint256 i = 0; i < n; i++) {
            naiveResult += aRaw[i] * sRaw[i];
        }
        naiveResult = naiveResult & Q_MASK;

        // Pack and compute via library
        uint256[] memory aPacked = LWEPacking.packVector12(aRaw);
        uint256[] memory sPacked = LWEPacking.packVector12(sRaw);
        uint256 libResult = LibLWE.innerProduct12(aPacked, sPacked, aPacked.length, Q_MASK);

        assertEq(libResult, naiveResult, "Packed 12-bit inner product must match naive");
    }

    // ──────────────────────────────────────────────────────────────────
    //  Edge-case / revert tests
    // ──────────────────────────────────────────────────────────────────

    function test_innerProduct16_revertOnOversizedNumWords() public {
        uint256[] memory a = new uint256[](2);
        uint256[] memory s = new uint256[](2);
        vm.expectRevert("numWords exceeds array length");
        harness.innerProduct16(a, s, 3, Q_PRIME);
    }

    function test_innerProduct12_revertOnOversizedNumWords() public {
        uint256[] memory a = new uint256[](1);
        uint256[] memory s = new uint256[](1);
        vm.expectRevert("numWords exceeds array length");
        harness.innerProduct12(a, s, 2, Q_MASK);
    }

    function test_innerProductSeedDerived_revertOnOversizedNumWords() public {
        uint256[] memory s = new uint256[](1);
        vm.expectRevert("numWords exceeds array length");
        harness.innerProductSeedDerived(bytes32(0), bytes32(0), 0, 0, s, 2, Q_PRIME);
    }

    function test_unpackVector12_emptyInput() public pure {
        uint256[] memory packed = new uint256[](0);
        uint256[] memory unpacked = LWEPacking.unpackVector12(packed, 0);
        assertEq(unpacked.length, 0);
    }

    function test_unpackVector12_revertOnInsufficientPacked() public {
        uint256[] memory packed = new uint256[](1); // holds 21 elements max
        vm.expectRevert("packed array too small for n");
        harness.unpackVector12(packed, 22); // needs 2 words
    }

    function test_expandKey_revertOnOversizedQ() public {
        vm.expectRevert("q must fit in 16-bit lanes");
        harness.expandKey(bytes32(0), 1, 65537);
    }

    function test_packVector16_revertOnOversizedQ() public {
        uint256[] memory input = new uint256[](1);
        input[0] = 0;
        vm.expectRevert("q must fit in 16-bit lanes");
        harness.packVector16(input, 65537);
    }
}
