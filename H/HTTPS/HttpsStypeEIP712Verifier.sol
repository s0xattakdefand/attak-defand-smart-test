// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract EIP712HTTPS {
    using ECDSA for bytes32;

    bytes32 public constant DOMAIN = keccak256("https://api.secure.com");

    function verify(address signer, string calldata data, bytes calldata sig) external pure returns (bool) {
        bytes32 msgHash = keccak256(abi.encodePacked(data));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN, msgHash));
        return digest.recover(sig) == signer;
    }
}
