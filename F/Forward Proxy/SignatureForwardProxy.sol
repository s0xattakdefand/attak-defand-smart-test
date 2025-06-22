// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract SignatureForwardProxy {
    using ECDSA for bytes32;

    mapping(address => uint256) public nonce;

    function forwardWithSig(
        address target,
        bytes calldata data,
        uint256 _nonce,
        bytes calldata sig
    ) external {
        bytes32 message = keccak256(abi.encodePacked(target, data, _nonce, msg.sender));
        require(message.toEthSignedMessageHash().recover(sig) == msg.sender, "Invalid signature");
        require(nonce[msg.sender] == _nonce, "Invalid nonce");

        nonce[msg.sender]++;
        (bool success, ) = target.call(data);
        require(success, "Forward failed");
    }
}
