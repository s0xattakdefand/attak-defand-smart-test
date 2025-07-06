// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
 * CFB MODE DEMO
 * Implements Cipher Feedback (CFB) mode encryption and decryption
 * per NIST SP 800-38A §6.3, for a block size of 256 bits (32 bytes)
 * using keccak256 as a toy “block cipher.”
 *
 * - Segment size (s) is in bytes and must satisfy 1 ≤ s ≤ 32.
 * - IV is 32 bytes (256 bits).
 * - Key is a 32-byte secret.
 *
 * WARNING: This is for demonstration only! keccak256 is _not_ an AES replacement.
 */
contract CFBModeDemo {
    bytes32 private immutable key;

    constructor(bytes32 _key) {
        key = _key;
    }

    /// @notice Encrypts plaintext in CFB mode.
    /// @param plaintext The data to encrypt; length must be a multiple of segSize.
    /// @param iv        The 32-byte initialization vector.
    /// @param segSize   Segment size in bytes (1..32).
    /// @return ciphertext The encrypted data.
    /// @return finalIV     The IV after all segments processed.
    function encryptCFB(
        bytes calldata plaintext,
        bytes32 iv,
        uint8 segSize
    )
        external
        view
        returns (bytes memory ciphertext, bytes32 finalIV)
    {
        require(segSize >= 1 && segSize <= 32, "segSize out of range");
        require(plaintext.length % segSize == 0, "plaintext not aligned");

        uint256 blocks = plaintext.length / segSize;
        ciphertext = new bytes(plaintext.length);
        bytes32 currentIV = iv;

        for (uint256 i = 0; i < blocks; i++) {
            // 1) Generate keystream block: E(key, IV)
            bytes32 ks = keccak256(abi.encodePacked(key, currentIV));

            // 2) Extract segment of keystream
            bytes memory ksSeg = new bytes(segSize);
            for (uint8 j = 0; j < segSize; j++) {
                ksSeg[j] = ks[j];
            }

            // 3) XOR keystream segment with plaintext segment
            bytes memory ptSeg = plaintext[i * segSize : i * segSize + segSize];
            bytes memory ctSeg = xorBytes(ptSeg, ksSeg);

            // 4) Write ciphertext segment
            for (uint8 j = 0; j < segSize; j++) {
                ciphertext[i * segSize + j] = ctSeg[j];
            }

            // 5) Update IV: shift left by segSize bytes, append ctSeg
            uint256 ivInt = uint256(currentIV);
            ivInt = (ivInt << (8 * segSize)) | bytesToUint(ctSeg);
            currentIV = bytes32(ivInt);
        }

        finalIV = currentIV;
    }

    /// @notice Decrypts CFB-mode ciphertext.
    /// @param ciphertext The data to decrypt; length must be a multiple of segSize.
    /// @param iv         The same IV used for encryption.
    /// @param segSize    Segment size in bytes (1..32).
    /// @return plaintext  The recovered plaintext.
    /// @return finalIV     The IV after all segments processed.
    function decryptCFB(
        bytes calldata ciphertext,
        bytes32 iv,
        uint8 segSize
    )
        external
        view
        returns (bytes memory plaintext, bytes32 finalIV)
    {
        require(segSize >= 1 && segSize <= 32, "segSize out of range");
        require(ciphertext.length % segSize == 0, "ciphertext not aligned");

        uint256 blocks = ciphertext.length / segSize;
        plaintext = new bytes(ciphertext.length);
        bytes32 currentIV = iv;

        for (uint256 i = 0; i < blocks; i++) {
            // 1) Generate keystream block: E(key, IV)
            bytes32 ks = keccak256(abi.encodePacked(key, currentIV));

            // 2) Extract segment of keystream
            bytes memory ksSeg = new bytes(segSize);
            for (uint8 j = 0; j < segSize; j++) {
                ksSeg[j] = ks[j];
            }

            // 3) XOR keystream segment with ciphertext segment to get plaintext
            bytes memory ctSeg = ciphertext[i * segSize : i * segSize + segSize];
            bytes memory ptSeg = xorBytes(ctSeg, ksSeg);

            // 4) Write plaintext segment
            for (uint8 j = 0; j < segSize; j++) {
                plaintext[i * segSize + j] = ptSeg[j];
            }

            // 5) Update IV: shift left by segSize bytes, append ctSeg
            uint256 ivInt = uint256(currentIV);
            ivInt = (ivInt << (8 * segSize)) | bytesToUint(ctSeg);
            currentIV = bytes32(ivInt);
        }

        finalIV = currentIV;
    }

    /// @dev XORs two equal-length byte arrays.
    function xorBytes(bytes memory a, bytes memory b) internal pure returns (bytes memory) {
        uint256 n = a.length;
        bytes memory c = new bytes(n);
        for (uint256 i = 0; i < n; i++) {
            c[i] = bytes1(uint8(a[i]) ^ uint8(b[i]));
        }
        return c;
    }

    /// @dev Converts up to 32 bytes to a right-aligned uint256.
    function bytesToUint(bytes memory b) internal pure returns (uint256) {
        uint256 x;
        for (uint i = 0; i < b.length; i++) {
            x = (x << 8) | uint8(b[i]);
        }
        return x;
    }
}
