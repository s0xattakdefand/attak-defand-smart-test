// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AuthenticationFactorVerifier - Simulates multi-factor identity validation

contract AuthenticationFactorVerifier {
    address public owner;

    struct UserAuth {
        bytes32 secretHash;      // Something you know
        address wallet;          // Something you have
        bool registered;
    }

    mapping(address => UserAuth) public users;
    mapping(bytes32 => bool) public usedNullifiers;

    event Authenticated(address indexed user, uint256 timestamp);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not authorized");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    /// @notice Register authentication factors for a user
    function registerAuthFactors(address user, bytes32 secretHash) external onlyOwner {
        users[user] = UserAuth(secretHash, user, true);
    }

    /// @notice Authenticate with secret + wallet signature (2FA)
    function authenticate(string calldata secret, bytes calldata signature) external {
        require(users[msg.sender].registered, "Not registered");

        // Check secret knowledge
        bytes32 hash = keccak256(abi.encodePacked(secret));
        require(hash == users[msg.sender].secretHash, "Invalid secret");

        // Check signature (user signs their own address as challenge)
        bytes32 digest = keccak256(abi.encodePacked(msg.sender));
        address signer = recoverSigner(digest, signature);
        require(signer == users[msg.sender].wallet, "Invalid signature");

        emit Authenticated(msg.sender, block.timestamp);
    }

    function recoverSigner(bytes32 hash, bytes memory sig) public pure returns (address) {
        require(sig.length == 65, "Bad sig");
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
        return ecrecover(hash, v, r, s);
    }
}
