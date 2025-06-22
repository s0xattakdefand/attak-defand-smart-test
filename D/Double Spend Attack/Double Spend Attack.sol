// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title DoubleSpendAttackDefense - Full Attack and Defense Simulation for Double Spend Vulnerabilities in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Token Contract (Vulnerable to Double Spend Replay)
contract InsecureDoubleSpendToken {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        (bool sent, ) = msg.sender.call{value: amount}("");
        require(sent, "Transfer failed");

        // BAD: balance updated AFTER external call
        balances[msg.sender] -= amount;
    }

    function getBalance(address user) external view returns (uint256) {
        return balances[user];
    }
}

/// @notice Secure Token Contract (Double Spend Hardened)
contract SecureDoubleSpendToken {
    mapping(address => uint256) public balances;
    mapping(address => uint256) public nonces;

    bool private locked;

    modifier lock() {
        require(!locked, "Reentrancy Guard");
        locked = true;
        _;
        locked = false;
    }

    function deposit() external payable lock {
        balances[msg.sender] += msg.value;
    }

    function safeWithdraw(uint256 amount, uint256 userNonce, uint8 v, bytes32 r, bytes32 s) external lock {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        require(userNonce == nonces[msg.sender], "Invalid nonce");

        bytes32 message = keccak256(abi.encodePacked(msg.sender, amount, userNonce, address(this), block.chainid));
        bytes32 ethSigned = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", message));

        address recovered = ecrecover(ethSigned, v, r, s);
        require(recovered == msg.sender, "Invalid signature");

        balances[msg.sender] -= amount;
        nonces[msg.sender]++;

        (bool sent, ) = msg.sender.call{value: amount}("");
        require(sent, "Transfer failed");
    }

    function getBalance(address user) external view returns (uint256) {
        return balances[user];
    }

    function getNonce(address user) external view returns (uint256) {
        return nonces[user];
    }
}

/// @notice Attack contract simulating double spend replay attacks
contract DoubleSpendIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function tryDoubleSpend(uint256 amount) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("withdraw(uint256)", amount)
        );
    }
}
