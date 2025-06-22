// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract HardenedBastion {
    using ECDSA for bytes32;

    address public backendSigner;
    address public internalTarget;

    mapping(address => bool) public whitelisted;
    mapping(address => uint256) public lastNonce;

    event Forwarded(address indexed sender, bytes data);
    event Whitelisted(address indexed user);

    constructor(address _target, address _backendSigner) {
        internalTarget = _target;
        backendSigner = _backendSigner;
    }

    modifier onlyWhitelisted() {
        require(whitelisted[msg.sender], "Not allowed");
        _;
    }

    function addWhitelist(
        address user,
        uint256 nonce,
        bytes calldata sig
    ) public {
        require(nonce > lastNonce[user], "Old or reused nonce");

        bytes32 hash = keccak256(abi.encodePacked(user, nonce));
        bytes32 signed = hash.toEthSignedMessageHash(); // ✅ FIXED here

        require(signed.recover(sig) == backendSigner, "Invalid signature");

        whitelisted[user] = true;
        lastNonce[user] = nonce;

        emit Whitelisted(user);
    }

    function forward(bytes calldata data) public onlyWhitelisted {
        (bool success, ) = internalTarget.call(data);
        require(success, "Forward failed");

        emit Forwarded(msg.sender, data);
    }
}
