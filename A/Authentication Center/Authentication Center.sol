// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AuthenticationCenter - Verifies user signatures and manages authentication events
contract AuthenticationCenter {
    address public admin;

    mapping(address => uint256) public nonces;
    mapping(address => bool) public authenticatedUsers;

    event UserAuthenticated(address indexed user, uint256 nonce, uint256 timestamp);

    constructor() {
        admin = msg.sender;
    }

    /// @notice Authenticates user via signed EIP-712 payload
    function authenticate(bytes32 hash, bytes calldata signature) external {
        address signer = recoverSigner(hash, signature);
        require(signer == msg.sender, "Invalid signer");
        require(nonces[signer] == uint256(bytes32(hash)), "Invalid nonce");
        authenticatedUsers[signer] = true;
        emit UserAuthenticated(signer, nonces[signer], block.timestamp);
        nonces[signer]++;
    }

    /// @notice Checks if user is currently authenticated
    function isAuthenticated(address user) external view returns (bool) {
        return authenticatedUsers[user];
    }

    /// @dev Recovers signer from hashed message
    function recoverSigner(bytes32 hash, bytes memory signature) internal pure returns (address) {
        require(signature.length == 65, "Invalid signature length");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }
        return ecrecover(hash, v, r, s);
    }
}
