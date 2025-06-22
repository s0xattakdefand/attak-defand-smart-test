// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

/**
 * @title VulnerableDecryptOracle
 * @notice A deliberately flawed decryption oracle. Anyone can submit an
 *         arbitrary ciphertext and receive its plaintext. This design is
 *         classic CCA-vulnerable, because an attacker can adapt queries
 *         based on previous decryptions to recover protected messages.
 *
 * @dev  **NEVER DEPLOY** something like this on mainnet.
 */
contract VulnerableDecryptOracle is Ownable, ReentrancyGuard {
    /* --------------------------------------------------------------------- */
    /*  Constants & storage                                                  */
    /* --------------------------------------------------------------------- */

    /// @dev Symmetric secret key (set once; private but *not* on-chain!)
    bytes32 private immutable _key;

    constructor(bytes32 key_) {
        _key = key_;
    }

    /* --------------------------------------------------------------------- */
    /*  Public interface                                                     */
    /* --------------------------------------------------------------------- */

    /**
     * @notice Decrypt an arbitrary ciphertext with the oracle’s secret.
     * @param ct  - raw ciphertext bytes (simple XOR scheme for demo only)
     * @return pt - recovered plaintext bytes
     *
     * @dev XOR is *not* secure!  Used here for clarity; real CCA exploits
     *      the same idea even with AES/RSA if an oracle is exposed.
     */
    function decrypt(bytes calldata ct)
        external
        view
        nonReentrant
        returns (bytes memory pt)
    {
        pt = _xorWithKey(ct);
    }

    /* --------------------------------------------------------------------- */
    /*  Internal helpers                                                     */
    /* --------------------------------------------------------------------- */

    function _xorWithKey(bytes calldata data)
        internal
        view
        returns (bytes memory out)
    {
        bytes32 k = _key;
        out = new bytes(data.length);

        for (uint256 i; i < data.length; ++i) {
            // Repeat-key XOR for simplicity
            out[i] = bytes1(uint8(data[i]) ^ uint8(k[i % 32]));
        }
    }
}
