// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Web3 Active Directory Authentication Library (ADAL)

interface IActiveDirectory {
    enum Role { NONE, VIEWER, OPERATOR, ADMIN }
    function roles(address user) external view returns (Role);
}

contract Web3ADAL {
    IActiveDirectory public directory;
    mapping(address => uint256) public nonces;

    event Authenticated(address indexed user, string purpose, uint256 nonce);
    event AttackDetected(address indexed attacker, string reason);

    constructor(address _directory) {
        directory = IActiveDirectory(_directory);
    }

    /// Authenticate using a signed payload
    function authenticate(
        string calldata purpose,
        uint256 nonce,
        bytes calldata signature
    ) external view returns (bool) {
        bytes32 payload = keccak256(abi.encodePacked(msg.sender, purpose, nonce));
        bytes32 digest = ECDSA.toEthSignedMessageHash(payload);
        address recovered = ECDSA.recover(digest, signature);

        if (recovered != msg.sender) {
            revert("Invalid signature");
        }

        if (nonce != nonces[msg.sender]) {
            revert("Replay attack");
        }

        if (directory.roles(recovered) == IActiveDirectory.Role.NONE) {
            revert("No role assigned");
        }

        return true;
    }

    /// Authenticate and increment nonce (stateful)
    function login(string calldata purpose, uint256 nonce, bytes calldata signature) external {
        require(authenticate(purpose, nonce, signature), "Auth failed");

        nonces[msg.sender]++;
        emit Authenticated(msg.sender, purpose, nonce);
    }

    /// Simulate attack
    function attackReplay(string calldata purpose, uint256 badNonce, bytes calldata sig) external {
        emit AttackDetected(msg.sender, "Simulated replay or drift");
        revert("Blocked attack");
    }
}

/// ECDSA lib
library ECDSA {
    function toEthSignedMessageHash(bytes32 hash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }
    function recover(bytes32 hash, bytes memory sig) internal pure returns (address) {
        require(sig.length == 65, "ECDSA: invalid sig");
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
        return ecrecover(hash, v, r, s);
    }
}
