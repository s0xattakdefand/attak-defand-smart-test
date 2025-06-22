// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Attack Types: Unauthorized Exec, Replay, Stale Auth
/// Defense Types: Signature Guard, Nonce Binding, Auth Log

contract AuthorizeProcessor {
    mapping(address => uint256) public nonces;
    mapping(bytes32 => bool) public usedAuthorizations;

    event Authorized(address indexed user, string action, uint256 nonce);
    event AttackDetected(address indexed attacker, string reason);

    /// DEFENSE: Process only if authorized by signature
    function authorizeAndProcess(
        string calldata action,
        uint256 nonce,
        bytes calldata signature
    ) external {
        bytes32 digest = keccak256(abi.encodePacked(msg.sender, action, nonce));
        bytes32 signedMsg = ECDSA.toEthSignedMessageHash(digest);
        address signer = ECDSA.recover(signedMsg, signature);

        require(signer == msg.sender, "Invalid signer");
        require(nonce == nonces[msg.sender], "Replay or mismatch");

        bytes32 authId = keccak256(abi.encodePacked(signer, action, nonce));
        require(!usedAuthorizations[authId], "Authorization already used");

        usedAuthorizations[authId] = true;
        nonces[msg.sender]++;

        emit Authorized(msg.sender, action, nonce);
        // 🔓 Process action logic here
    }

    /// ATTACK SIMULATION: Reuse same signature/nonce
    function attackReplay(string calldata action, uint256 oldNonce, bytes calldata signature) external {
        emit AttackDetected(msg.sender, "Replay attack attempt");
        revert("Blocked replay");
    }
}

/// ECDSA utility lib
library ECDSA {
    function toEthSignedMessageHash(bytes32 hash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }

    function recover(bytes32 hash, bytes memory sig) internal pure returns (address) {
        require(sig.length == 65, "ECDSA: invalid sig length");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(sig, 0x20))
            s := mload(add(sig, 0x40))
            v := byte(0, mload(add(sig, 0x60)))
        }
        return ecrecover(hash, v, r, s);
    }
}
