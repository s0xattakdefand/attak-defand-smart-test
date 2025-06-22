// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title DualAuthorizationAttackDefense - Full Attack and Defense Simulation for Dual Authorization Systems in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Dual Authorization Contract (Vulnerable to Single Signer or Replay)
contract InsecureDualAuth {
    address public signer1;
    address public signer2;

    constructor(address _signer1, address _signer2) {
        signer1 = _signer1;
        signer2 = _signer2;
    }

    function criticalAction(bytes32 hash, uint8 v, bytes32 r, bytes32 s) external {
        // Only verifies one signer - BAD!
        address recovered = ecrecover(hash, v, r, s);
        require(recovered == signer1 || recovered == signer2, "Unauthorized signer");

        // No double signature check, no nonce check, replay possible!
        // Perform critical logic
    }
}

/// @notice Secure Dual Authorization Contract (Full Defense)
contract SecureDualAuth {
    address public signer1;
    address public signer2;
    mapping(bytes32 => bool) public usedHashes;
    bool private locked;

    constructor(address _signer1, address _signer2) {
        signer1 = _signer1;
        signer2 = _signer2;
    }

    modifier lock() {
        require(!locked, "Reentrancy Guard");
        locked = true;
        _;
        locked = false;
    }

    function criticalAction(
        uint256 nonce,
        uint256 expiry,
        bytes calldata payload,
        uint8 v1,
        bytes32 r1,
        bytes32 s1,
        uint8 v2,
        bytes32 r2,
        bytes32 s2
    ) external lock {
        require(block.timestamp <= expiry, "Signature expired");

        bytes32 hash = keccak256(abi.encodePacked(nonce, expiry, payload, address(this), block.chainid));
        require(!usedHashes[hash], "Hash already used");

        address recovered1 = ecrecover(
            keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash)),
            v1, r1, s1
        );
        address recovered2 = ecrecover(
            keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash)),
            v2, r2, s2
        );

        require(recovered1 != recovered2, "Signers must be different");
        require((recovered1 == signer1 || recovered1 == signer2), "Signer1 unauthorized");
        require((recovered2 == signer1 || recovered2 == signer2), "Signer2 unauthorized");

        usedHashes[hash] = true;

        // Critical secured logic here...
    }
}

/// @notice Attack contract trying to fake dual authorization
contract DualAuthIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function trySingleSignature(bytes32 hash, uint8 v, bytes32 r, bytes32 s) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("criticalAction(bytes32,uint8,bytes32,bytes32)", hash, v, r, s)
        );
    }
}
