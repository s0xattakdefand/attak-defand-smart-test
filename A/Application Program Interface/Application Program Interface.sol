// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract SecureAPIGateway {
    mapping(address => uint256) public nonces;
    mapping(address => bool) public trustedSigners;

    event APICall(address indexed user, string action, uint256 nonce);
    event SpoofAttempt(address indexed actor, string reason);

    constructor(address[] memory signers) {
        for (uint i = 0; i < signers.length; i++) {
            trustedSigners[signers[i]] = true;
        }
    }

    function callAPI(string calldata action, uint256 nonce, bytes calldata signature) external {
        bytes32 message = getMessageHash(action, nonce);
        address signer = recoverSigner(message, signature);

        if (!trustedSigners[signer]) {
            emit SpoofAttempt(msg.sender, "Untrusted signer");
            revert("Untrusted API caller");
        }

        require(nonces[signer] < nonce, "Replay detected");
        nonces[signer] = nonce;

        emit APICall(signer, action, nonce);
        // logic: e.g., update contract state or trigger response
    }

    function getMessageHash(string memory action, uint256 nonce) public pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(abi.encodePacked(action, nonce))));
    }

    function recoverSigner(bytes32 hash, bytes memory sig) public pure returns (address) {
        require(sig.length == 65, "Invalid signature");
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
}
