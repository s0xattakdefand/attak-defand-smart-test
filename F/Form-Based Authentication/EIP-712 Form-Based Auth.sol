// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract TypedFormAuth {
    using ECDSA for bytes32;

    bytes32 public DOMAIN_SEPARATOR;
    bytes32 public constant LOGIN_TYPEHASH = keccak256("Login(address user,uint256 nonce)");

    mapping(address => bool) public authenticated;

    constructor() {
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("TypedFormAuth"),
                keccak256("1"),
                block.chainid,
                address(this)
            )
        );
    }

    function loginTyped(uint256 nonce, bytes calldata signature) external {
        bytes32 structHash = keccak256(abi.encode(LOGIN_TYPEHASH, msg.sender, nonce));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
        address signer = digest.recover(signature);
        require(signer == msg.sender, "Invalid signature");
        authenticated[msg.sender] = true;
    }
}
