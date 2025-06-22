// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract ARAccessVerifier {
    address public oracle;
    mapping(bytes32 => bool) public usedProofs;

    event AccessGranted(address indexed user, bytes32 sceneId);
    event AccessRejected(address indexed user, string reason);

    constructor(address _oracle) {
        oracle = _oracle;
    }

    function submitARProof(bytes32 sceneId, bytes calldata signature) external {
        bytes32 proofHash = keccak256(abi.encodePacked(msg.sender, sceneId));
        require(!usedProofs[proofHash], "Proof already used");

        // Verify signature from off-chain oracle (e.g., GPS validator, AR engine)
        address signer = recoverSigner(proofHash, signature);
        require(signer == oracle, "Invalid AR proof");

        usedProofs[proofHash] = true;
        emit AccessGranted(msg.sender, sceneId);
    }

    function recoverSigner(bytes32 hash, bytes memory sig) internal pure returns (address) {
        bytes32 prefixed = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
        (bytes32 r, bytes32 s, uint8 v) = splitSig(sig);
        return ecrecover(prefixed, v, r, s);
    }

    function splitSig(bytes memory sig) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
        require(sig.length == 65, "Invalid sig");
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
    }
}
