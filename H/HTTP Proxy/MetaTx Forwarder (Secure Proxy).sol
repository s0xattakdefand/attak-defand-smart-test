// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract SecureForwardProxy {
    using ECDSA for bytes32;

    mapping(address => uint256) public nonces;

    event Executed(address user, address target);

    function forward(address user, address target, bytes calldata data, bytes calldata sig) external {
        bytes32 digest = keccak256(abi.encodePacked(user, target, data, nonces[user])).toEthSignedMessageHash();
        address signer = digest.recover(sig);

        require(signer == user, "Invalid signer");
        nonces[user]++;

        (bool ok, ) = target.call(data);
        require(ok, "Forwarded call failed");

        emit Executed(user, target);
    }
}
