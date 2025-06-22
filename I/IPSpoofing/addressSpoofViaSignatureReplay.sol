// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract SpoofedAccess {
    using ECDSA for bytes32;

    mapping(address => bool) public isAuthorized;

    function authorize(bytes calldata signature) external {
        bytes32 message = keccak256(abi.encodePacked(msg.sender)).toEthSignedMessageHash();
        address signer = message.recover(signature);

        // ❌ Attacker tricks contract by replaying an old signature
        require(signer == msg.sender, "Invalid identity");
        isAuthorized[msg.sender] = true;
    }
}
