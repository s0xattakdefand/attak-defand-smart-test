// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CSCPublicKeyRegistry {
    address public admin;
    mapping(address => bool) public trustedSigners;

    event SignerAdded(address signer);
    event SignerRemoved(address signer);
    event ContentVerified(address signer, bytes32 hash);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function addSigner(address signer) external onlyAdmin {
        trustedSigners[signer] = true;
        emit SignerAdded(signer);
    }

    function removeSigner(address signer) external onlyAdmin {
        trustedSigners[signer] = false;
        emit SignerRemoved(signer);
    }

    function verifyContent(bytes32 hash, bytes memory signature) external returns (bool) {
        address recovered = recoverSigner(hash, signature);
        bool isTrusted = trustedSigners[recovered];
        if (isTrusted) {
            emit ContentVerified(recovered, hash);
        }
        return isTrusted;
    }

    function recoverSigner(bytes32 hash, bytes memory sig) internal pure returns (address) {
        return
            keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash))
                .recover(sig);
    }
}

library ECDSA {
    function recover(bytes32 hash, bytes memory signature) internal pure returns (address) {
        (bytes32 r, bytes32 s, uint8 v) = splitSignature(signature);
        return ecrecover(hash, v, r, s);
    }

    function splitSignature(bytes memory sig) internal pure returns (bytes32, bytes32, uint8) {
        require(sig.length == 65, "Invalid signature length");
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
        return (r, s, v);
    }
}
