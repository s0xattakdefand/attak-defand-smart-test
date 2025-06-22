// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract SignedFingerprintRegistry {
    using ECDSA for bytes32;

    mapping(address => string) public fingerprints;

    function submitFingerprint(string calldata label, bytes calldata sig) external {
        bytes32 hash = keccak256(abi.encodePacked(label, msg.sender));
        address recovered = hash.toEthSignedMessageHash().recover(sig);
        require(recovered == msg.sender, "Invalid signature");
        fingerprints[msg.sender] = label;
    }

    function getFingerprint(address user) external view returns (string memory) {
        return fingerprints[user];
    }
}
