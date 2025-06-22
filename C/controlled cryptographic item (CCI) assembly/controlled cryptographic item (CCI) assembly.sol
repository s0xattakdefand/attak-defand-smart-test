// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title CCIAssemblyGate — Inline assembly-controlled cryptographic access
contract CCIAssemblyGate {
    bytes32 private cciHash;
    address public trustedSigner;

    event AccessGranted(address indexed user);
    event SignatureVerified(address indexed signer);
    event MemoryWiped(uint256 location);

    constructor(string memory secret, address signer) {
        cciHash = keccak256(abi.encodePacked(secret));
        trustedSigner = signer;
    }

    /// @notice Access gate via preimage and signature
    function accessCCI(string calldata secret, bytes32 hash, uint8 v, bytes32 r, bytes32 s) external {
        assembly {
            // 1. Memory cleanup pre-use
            mstore(0x00, 0)
            log1(0x00, 0x20, keccak256("MemoryWiped(uint256)"))

            // 2. Load calldata offset for `secret`
            let ptr := calldataload(4) // secret starts after function selector
            let len := calldataload(ptr)
            let secretOffset := add(ptr, 0x20)

            // 3. Hash the secret
            let h := keccak256(secretOffset, len)

            // 4. Compare to cciHash (from storage slot 0)
            if iszero(eq(sload(0x0), h)) {
                revert(0, 0)
            }

            // 5. ecrecover to validate signer
            mstore(0x20, hash)
            mstore(0x00, r)
            mstore(0x40, s)
            mstore(0x60, v)

            let signer := staticcall(
                gas(), 
                0x01, // precompile for ecrecover
                0x00, 
                0x80, 
                0x00, 
                0x20
            )

            let recovered := mload(0x00)

            if iszero(eq(recovered, sload(0x1))) {
                revert(0, 0)
            }

            // 6. Log access
            log1(0x00, 0x20, keccak256("AccessGranted(address)"))
            log1(0x00, 0x20, keccak256("SignatureVerified(address)"))
        }
    }

    function rotateSecret(string calldata newSecret) external {
        require(msg.sender == trustedSigner, "Not trusted");
        cciHash = keccak256(abi.encodePacked(newSecret));
    }
}
