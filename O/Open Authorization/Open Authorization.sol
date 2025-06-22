// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Attack Types: Authorization Forgery, Scope Escalation, Replay Attack
/// Defense Types: Authorization Signature Verification, Scope Binding, Nonce and Expiry Enforcement

contract OpenAuthorization {
    address public owner;
    mapping(bytes32 => bool) public usedAuthorizations;
    mapping(address => uint256) public balances;

    event AuthorizationUsed(address indexed user, string action);
    event Deposit(address indexed user, uint256 amount);

    constructor() {
        owner = msg.sender;
    }

    /// Deposit funds
    function deposit() external payable {
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    /// ATTACK Simulation: Forged authorization
    function attackForgeAuthorization(address victim) external {
        balances[msg.sender] += balances[victim]; // steal balance
        balances[victim] = 0;
        emit AuthorizationUsed(msg.sender, "ForgedTransfer");
    }

    /// DEFENSE: Secure delegated action with verified signed authorization
    function performAuthorizedAction(
        address user,
        string memory action,
        uint256 nonce,
        uint256 expiry,
        bytes32 hash,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        require(block.timestamp <= expiry, "Authorization expired");
        require(!usedAuthorizations[hash], "Authorization already used");

        bytes32 expectedHash = keccak256(abi.encodePacked(user, action, nonce, expiry));
        require(hash == expectedHash, "Hash mismatch");

        address signer = ecrecover(toEthSignedMessageHash(expectedHash), v, r, s);
        require(signer == user, "Invalid signature");

        usedAuthorizations[hash] = true;

        // Example action: withdraw balance (very limited scope)
        if (keccak256(abi.encodePacked(action)) == keccak256(abi.encodePacked("withdrawBalance"))) {
            uint256 amount = balances[user];
            require(amount > 0, "No balance to withdraw");

            balances[user] = 0;
            payable(user).transfer(amount);
            emit AuthorizationUsed(user, action);
        } else {
            revert("Invalid action");
        }
    }

    // Utility: Ethereum Signed Message prefix
    function toEthSignedMessageHash(bytes32 hash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }

    // Helper to generate hash offchain
    function generateAuthorizationHash(address user, string memory action, uint256 nonce, uint256 expiry) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(user, action, nonce, expiry));
    }

    // View balance
    function viewBalance(address user) external view returns (uint256) {
        return balances[user];
    }
}
