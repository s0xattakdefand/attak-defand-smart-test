// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract TrustedAMIVerifier {
    mapping(address => bool) public trustedAMIs;
    mapping(bytes32 => bool) public usedHashes;

    event TrustedAMIAdded(address indexed signer);
    event AMIActionVerified(address indexed signer, string action);

    constructor(address initialAMI) {
        trustedAMIs[initialAMI] = true;
        emit TrustedAMIAdded(initialAMI);
    }

    function addTrustedAMI(address signer) external {
        // This would normally be restricted to an admin in production
        trustedAMIs[signer] = true;
        emit TrustedAMIAdded(signer);
    }

    /// @notice Verifies a message signed by a trusted AMI
    function verifyAMIAction(
        string calldata action,
        uint256 nonce,
        bytes calldata signature
    ) external returns (bool) {
        bytes32 hash = getMessageHash(action, nonce);
        require(!usedHashes[hash], "Replay detected");

        address signer = recoverSigner(hash, signature);
        require(trustedAMIs[signer], "Signer not trusted");

        usedHashes[hash] = true;

        emit AMIActionVerified(signer, action);
        return true;
    }

    /// @notice EIP-191 formatted hash
    function getMessageHash(string memory action, uint256 nonce) public pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(abi.encodePacked(action, nonce))));
    }

    function recoverSigner(bytes32 messageHash, bytes memory sig) public pure returns (address) {
        require(sig.length == 65, "Bad signature length");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
        return ecrecover(messageHash, v, r, s);
    }
}
