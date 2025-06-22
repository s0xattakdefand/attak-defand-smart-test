// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IPoseidonVerifier {
    function verify(bytes32 input, bytes32 expectedHash) external view returns (bool);
}

contract CryptoVerifier {
    address public admin;
    mapping(bytes32 => bool) public usedSignatures;
    IPoseidonVerifier public poseidon;

    event Verified(address indexed user, bytes32 msgHash);
    event PoseidonVerified(bytes32 input, bytes32 root);

    constructor(address _verifier) {
        admin = msg.sender;
        poseidon = IPoseidonVerifier(_verifier);
    }

    function verifySig(bytes32 msgHash, bytes memory sig) external {
        require(!usedSignatures[msgHash], "Replay");
        address signer = recover(msgHash, sig);
        require(signer != address(0), "Invalid sig");
        usedSignatures[msgHash] = true;
        emit Verified(signer, msgHash);
    }

    function verifyPoseidon(bytes32 input, bytes32 expectedHash) external view returns (bool) {
        bool ok = poseidon.verify(input, expectedHash);
        require(ok, "Invalid poseidon proof");
        emit PoseidonVerified(input, expectedHash);
        return true;
    }

    function recover(bytes32 hash, bytes memory sig) internal pure returns (address) {
        require(sig.length == 65, "Bad length");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }

        // Enforce canonical EIP-2
        require(uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, "Invalid s");
        require(v == 27 || v == 28, "Invalid v");

        return ecrecover(toEthSigned(hash), v, r, s);
    }

    function toEthSigned(bytes32 h) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
    }
}
