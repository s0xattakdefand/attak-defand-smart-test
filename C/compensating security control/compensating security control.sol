// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CompensatingAccessController {
    address public admin;
    address public signer;

    mapping(address => bool) public allowed;

    event AccessGranted(address indexed user);
    event AccessRevoked(address indexed user);

    constructor(address _signer) {
        admin = msg.sender;
        signer = _signer;
    }

    function grantAccess(bytes calldata signature) external {
        require(!allowed[msg.sender], "Already allowed");

        bytes32 message = keccak256(abi.encodePacked(msg.sender));
        bytes32 ethSigned = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", message));
        require(recover(ethSigned, signature) == signer, "Invalid signature");

        allowed[msg.sender] = true;
        emit AccessGranted(msg.sender);
    }

    function revokeAccess(address user) external {
        require(msg.sender == admin, "Only admin");
        allowed[user] = false;
        emit AccessRevoked(user);
    }

    function hasAccess(address user) external view returns (bool) {
        return allowed[user];
    }

    function recover(bytes32 hash, bytes memory sig) internal pure returns (address) {
        require(sig.length == 65, "Invalid length");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
        return ecrecover(hash, v, r, s);
    }
}
