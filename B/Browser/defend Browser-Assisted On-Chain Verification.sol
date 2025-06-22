// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract BrowserVerifiedSession {
    using ECDSA for bytes32;

    address public trustedFrontend;
    mapping(address => uint256) public lastNonce;

    event SessionStarted(address user, uint256 nonce);

    constructor(address _frontend) {
        trustedFrontend = _frontend;
    }

    function verifySession(uint256 nonce, bytes calldata sig) external {
        require(nonce > lastNonce[msg.sender], "Nonce too low");
        bytes32 hash = keccak256(abi.encodePacked(msg.sender, nonce)).toEthSignedMessageHash();
        require(hash.recover(sig) == trustedFrontend, "Invalid signature");

        lastNonce[msg.sender] = nonce;
        emit SessionStarted(msg.sender, nonce);
    }
}
