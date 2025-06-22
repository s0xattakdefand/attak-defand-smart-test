// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CommsSecurityGuard {
    address public trustedSigner;
    mapping(bytes32 => bool) public processedMessages;

    event MessageVerified(bytes32 indexed msgId, address sender);

    constructor(address _trustedSigner) {
        trustedSigner = _trustedSigner;
    }

    function verifyMessage(
        bytes calldata payload,
        bytes calldata signature,
        bytes32 msgId,
        uint32 domainId
    ) external {
        require(!processedMessages[msgId], "Replay detected");

        // Integrity & authentication
        bytes32 digest = keccak256(abi.encodePacked(payload, msg.sender, domainId, msgId));
        require(recover(digest, signature) == trustedSigner, "Invalid signature");

        processedMessages[msgId] = true;
        emit MessageVerified(msgId, msg.sender);
    }

    function recover(bytes32 hash, bytes memory sig) internal pure returns (address) {
        require(sig.length == 65, "Invalid length");
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
        return ecrecover(toEthSigned(hash), v, r, s);
    }

    function toEthSigned(bytes32 h) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
    }
}
