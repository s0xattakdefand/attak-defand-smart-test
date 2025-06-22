// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract MetaTxSecure {
    using ECDSA for bytes32;

    mapping(address => uint256) public nonces;
    bytes32 public constant DOMAIN = keccak256("MetaTxSecure-v1");

    event Executed(address from, address to, uint256 value);

    function relay(
        address to,
        uint256 value,
        uint256 nonce,
        bytes calldata sig
    ) external {
        require(nonce == nonces[msg.sender], "Invalid nonce");

        bytes32 hash = keccak256(abi.encodePacked(DOMAIN, msg.sender, to, value, nonce));
        address signer = hash.toEthSignedMessageHash().recover(sig);
        require(signer == msg.sender, "Invalid signer");

        nonces[msg.sender] += 1;

        (bool success, ) = to.call{value: value}("");
        require(success, "Failed");

        emit Executed(msg.sender, to, value);
    }

    receive() external payable {}
}
