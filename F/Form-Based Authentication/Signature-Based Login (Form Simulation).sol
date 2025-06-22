// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract SignatureFormAuth {
    using ECDSA for bytes32;

    mapping(address => bool) public authenticated;

    event LoggedIn(address indexed user);

    function loginWithSignature(bytes32 nonce, bytes calldata signature) external {
        bytes32 message = keccak256(abi.encodePacked(msg.sender, nonce));
        address signer = message.toEthSignedMessageHash().recover(signature);
        require(signer == msg.sender, "Invalid signature");
        authenticated[msg.sender] = true;
        emit LoggedIn(msg.sender);
    }

    function isAuthenticated(address user) external view returns (bool) {
        return authenticated[user];
    }
}
