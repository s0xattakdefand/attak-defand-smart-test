// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title Deterministic Random Bit Generator (DRBG)
 * @notice A simple, keccak256-based deterministic RNG with seeding, reseeding,
 *         and reproducible output. NOT a drop-in replacement for NIST SP 800-90A;
 *         it is an educational, deterministic generator for contracts/tests.
 *
 * Design (counter-mode over keccak256):
 *   state.key      — 32-byte internal key
 *   state.counter  — monotonically increasing counter
 *   output block   — keccak256(key || counter || additionalData)
 *   state evolve   — key <- keccak256(key || block || additionalData), counter++
 *
 * Security note:
 *   On-chain “randomness” from a single contract is predictable to observers.
 *   Use this DRBG for deterministic simulations, test fixtures, loot tables,
 *   or games that accept determinism, not for adversarial settings with value at risk.
 */
contract DRBG {
    // --- State ---
    bytes32 private _key;
    uint128 private _counter;
    bool    private _initialized;

    address public owner;

    // --- Events ---
    event Initialized(bytes32 seed, bytes32 personalization);
    event Reseeded(bytes32 entropy);
    event Generated(uint256 blocks, bytes32 lastBlock);

    // --- Errors ---
    error NotOwner();
    error AlreadyInitialized();
    error NotInitialized();
    error ZeroBlocks();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    /**
     * @notice One-time initialization with seed and optional personalization.
     * @dev For reproducibility, pass the same seed/personalization to get the same stream.
     */
    function initialize(bytes32 seed, bytes32 personalization) external onlyOwner {
        if (_initialized) revert AlreadyInitialized();
        // Domain separation tag to avoid accidental cross-protocol collisions.
        _key = keccak256(abi.encodePacked(
            "DRBG:v1:initialize", seed, personalization, address(this)
        ));
        _counter = 1;
        _initialized = true;
        emit Initialized(seed, personalization);
    }

    /**
     * @notice Mix fresh entropy into the generator.
     * @dev Can be called multiple times; keeps determinism relative to the call history.
     */
    function reseed(bytes32 entropy) external onlyOwner {
        if (!_initialized) revert NotInitialized();
        _key = keccak256(abi.encodePacked("DRBG:v1:reseed", _key, entropy));
        unchecked { _counter += 1; }
        emit Reseeded(entropy);
    }

    /**
     * @notice Generate a single 32-byte block.
     * @param additionalData Optional domain/context data mixed into this step (use 0x0 if unused).
     */
    function generate(bytes32 additionalData) public onlyOwner returns (bytes32 out) {
        if (!_initialized) revert NotInitialized();
        // Output block
        out = keccak256(abi.encodePacked(_key, _counter, additionalData));
        // Evolve state
        _key = keccak256(abi.encodePacked("DRBG:v1:step", _key, out, additionalData));
        unchecked { _counter += 1; }
        emit Generated(1, out);
    }

    /**
     * @notice Generate N blocks (32*N bytes) in one call.
     * @param blocks Number of 32-byte blocks to produce (must be > 0).
     * @param additionalData Optional per-call additional data (use 0x0 if unused).
     * @return output Array of bytes32 blocks.
     */
    function generateBlocks(uint256 blocks, bytes32 additionalData)
        external
        onlyOwner
        returns (bytes32[] memory output)
    {
        if (!_initialized) revert NotInitialized();
        if (blocks == 0) revert ZeroBlocks();

        output = new bytes32[](blocks);
        bytes32 k = _key;
        uint128 c = _counter;

        // Loop in memory for gas efficiency; commit at end
        for (uint256 i = 0; i < blocks; i++) {
            bytes32 out = keccak256(abi.encodePacked(k, c, additionalData));
            output[i] = out;
            k = keccak256(abi.encodePacked("DRBG:v1:step", k, out, additionalData));
            unchecked { c += 1; }
        }

        _key = k;
        _counter = c;
        emit Generated(blocks, output[blocks - 1]);
    }

    /**
     * @notice Generate a uint256, optionally reduced modulo `mod`.
     * @dev If `mod` is zero, returns an unconstrained uint256.
     */
    function generateUint(bytes32 additionalData, uint256 mod) external onlyOwner returns (uint256 rnd) {
        bytes32 out = generate(additionalData);
        rnd = uint256(out);
        if (mod != 0) {
            rnd %= mod;
        }
    }

    /**
     * @notice Public, read-only peek at the next block without advancing the state.
     * @dev Useful for deterministic previews in off-chain tooling. Not “secure”.
     */
    function peekNext(bytes32 additionalData) external view returns (bytes32) {
        if (!_initialized) revert NotInitialized();
        return keccak256(abi.encodePacked(_key, _counter, additionalData));
    }

    // --- Introspection ---

    function initialized() external view returns (bool) {
        return _initialized;
    }

    function counter() external view returns (uint128) {
        return _counter;
    }

    /**
     * @notice Return a commitment to the internal key (not the key itself).
     * @dev Helpful for audits without revealing state (still deterministic).
     */
    function keyCommitment() external view returns (bytes32) {
        if (!_initialized) revert NotInitialized();
        return keccak256(abi.encodePacked("DRBG:v1:keyCommit", _key));
    }

    // --- Ownership ---

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "newOwner=0");
        owner = newOwner;
    }
}
