// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract NonceAuthenticator {
    mapping(address => uint256) public nonces;

    event Authenticated(address indexed user, uint256 nonce);

    /// @notice Authenticate a signed message using nonce
    function authenticate(bytes calldata signature) external {
        uint256 userNonce = nonces[msg.sender];
        bytes32 hash = getMessageHash(msg.sender, userNonce);
        address signer = recoverSigner(hash, signature);

        require(signer == msg.sender, "Invalid signature");

        emit Authenticated(msg.sender, userNonce);
        nonces[msg.sender] += 1;
    }

    /// @notice Generate the message hash to be signed
    function getMessageHash(address user, uint256 nonce) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(user, nonce));
    }

    /// @notice Recover signer from signature
    function recoverSigner(bytes32 messageHash, bytes memory signature) internal pure returns (address) {
        bytes32 ethSignedHash = toEthSignedMessageHash(messageHash);
        (bytes32 r, bytes32 s, uint8 v) = splitSignature(signature);
        return ecrecover(ethSignedHash, v, r, s);
    }

    /// @notice Convert to Ethereum Signed Message Hash
    function toEthSignedMessageHash(bytes32 hash) public pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }

    /// @notice Split signature into r, s, v
    function splitSignature(bytes memory sig)
        public pure returns (bytes32 r, bytes32 s, uint8 v)
    {
        require(sig.length == 65, "Invalid signature length");

        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
    }

    /// @notice Get current nonce for user
    function getCurrentNonce(address user) external view returns (uint256) {
        return nonces[user];
    }
}
