// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ParityAttackDefense - Attack and Defense Simulation for Parity Issues in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure State Management (No Parity Checking Across Replicas)
contract InsecureParity {
    mapping(address => uint256) public balances;

    event BalanceUpdated(address indexed user, uint256 newBalance);

    function updateBalance(address user, uint256 newBalance) external {
        // 🔥 Anyone can desynchronize replica states!
        balances[user] = newBalance;
        emit BalanceUpdated(user, newBalance);
    }
}

/// @notice Secure Parity-Checked State (State Hash Validation and Consensus Update Protection)
import "@openzeppelin/contracts/access/Ownable.sol";

contract SecureParity is Ownable {
    mapping(address => uint256) private balances;
    bytes32 public stateHash;
    uint256 public version;

    event BalanceUpdated(address indexed user, uint256 newBalance, bytes32 newStateHash);

    constructor() {
        stateHash = keccak256(abi.encodePacked(address(this), block.chainid, version));
    }

    function updateBalance(address user, uint256 newBalance) external onlyOwner {
        balances[user] = newBalance;
        version++;
        stateHash = keccak256(abi.encodePacked(address(this), block.chainid, version, user, newBalance));
        emit BalanceUpdated(user, newBalance, stateHash);
    }

    function getBalance(address user) external view returns (uint256) {
        return balances[user];
    }

    function verifyStateHash(bytes32 externalHash) external view returns (bool) {
        return stateHash == externalHash;
    }
}

/// @notice Attack contract simulating state drift injection
contract ParityIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function driftState(address victim, uint256 fakeBalance) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("updateBalance(address,uint256)", victim, fakeBalance)
        );
    }
}
