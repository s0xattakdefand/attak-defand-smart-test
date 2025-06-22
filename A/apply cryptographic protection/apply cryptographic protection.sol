// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract CryptoProtected {
    mapping(address => uint256) public nonces;

    event Verified(address signer, string action);

    function verifySignature(
        string calldata action,
        uint256 nonce,
        bytes calldata signature
    ) external returns (bool) {
        require(nonce == nonces[msg.sender] + 1, "Invalid nonce");
        bytes32 messageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(abi.encodePacked(action, nonce))));
        address signer = recoverSigner(messageHash, signature);
        require(signer == msg.sender, "Bad signature");
        nonces[msg.sender] = nonce;

        emit Verified(signer, action);
        return true;
    }

    function recoverSigner(bytes32 hash, bytes memory sig) internal pure returns (address) {
        require(sig.length == 65, "Bad sig length");
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
        return ecrecover(hash, v, r, s);
    }
}
