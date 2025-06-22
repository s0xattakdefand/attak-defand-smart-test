// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract AntiSpoofVerifier {
    mapping(address => bool) public trustedSigners;
    mapping(bytes32 => bool) public usedHashes;

    event Verified(address indexed signer, string action);
    event SpoofAttempt(address indexed sender, string reason);

    constructor(address[] memory trusted) {
        for (uint i = 0; i < trusted.length; i++) {
            trustedSigners[trusted[i]] = true;
        }
    }

    function verify(
        string calldata action,
        uint256 nonce,
        bytes calldata signature
    ) external returns (bool) {
        bytes32 message = getMessageHash(action, nonce);
        require(!usedHashes[message], "Replay detected");

        address signer = recoverSigner(message, signature);
        if (!trustedSigners[signer]) {
            emit SpoofAttempt(msg.sender, "Signer not trusted");
            return false;
        }

        usedHashes[message] = true;
        emit Verified(signer, action);
        return true;
    }

    function getMessageHash(string memory action, uint256 nonce) public pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(abi.encodePacked(action, nonce))));
    }

    function recoverSigner(bytes32 hash, bytes memory sig) public pure returns (address) {
        require(sig.length == 65, "Bad sig length");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
        return ecrecover(hash, v, r, s);
    }

    function isTrusted(address signer) external view returns (bool) {
        return trustedSigners[signer];
    }
}
