// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Web3 Message Auth System with AAD support
contract AADValidator {
    address public admin;

    event Verified(address signer, bytes32 aad, string action);

    constructor() {
        admin = msg.sender;
    }

    function getAAD(
        address user,
        string memory domain,
        uint256 nonce,
        string memory role
    ) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(user, domain, nonce, role));
    }

    function verifyAADSignature(
        bytes32 aad,
        string memory action,
        bytes calldata signature
    ) external view returns (address signer) {
        bytes32 hash = keccak256(abi.encodePacked(aad, action));
        bytes32 ethSigned = toEthSignedMessageHash(hash);
        signer = recover(ethSigned, signature);
        emit Verified(signer, aad, action);
    }

    function toEthSignedMessageHash(bytes32 hash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }

    function recover(bytes32 hash, bytes memory sig) internal pure returns (address) {
        require(sig.length == 65, "Invalid sig length");
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
        return ecrecover(hash, v, r, s);
    }
}
