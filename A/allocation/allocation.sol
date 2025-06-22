// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract SecureAllocator is AccessControl {
    bytes32 public constant ALLOCATOR_ROLE = keccak256("ALLOCATOR_ROLE");
    IERC20 public immutable rewardToken;

    mapping(address => uint256) public allocated;
    mapping(address => bool) public hasClaimed;

    event AllocationSet(address indexed user, uint256 amount);
    event AllocationClaimed(address indexed user, uint256 amount);

    constructor(address token, address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ALLOCATOR_ROLE, admin);
        rewardToken = IERC20(token);
    }

    /// @notice Allocate tokens to a user
    function setAllocation(address user, uint256 amount) external onlyRole(ALLOCATOR_ROLE) {
        require(user != address(0), "Invalid user");
        require(amount > 0, "Zero amount");
        require(allocated[user] == 0, "Already allocated");
        allocated[user] = amount;
        emit AllocationSet(user, amount);
    }

    /// @notice User claims their allocation once
    function claim() external {
        require(!hasClaimed[msg.sender], "Already claimed");
        uint256 amount = allocated[msg.sender];
        require(amount > 0, "No allocation");

        hasClaimed[msg.sender] = true;
        rewardToken.transfer(msg.sender, amount);
        emit AllocationClaimed(msg.sender, amount);
    }

    /// @notice Admin view: check allocation and status
    function getAllocationInfo(address user) external view returns (uint256 amount, bool claimed) {
        return (allocated[user], hasClaimed[user]);
    }
}
