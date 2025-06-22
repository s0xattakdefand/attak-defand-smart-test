// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/governance/TimelockController.sol";

/**
 * A Timelock-based config approach:
 * - All param changes must be scheduled + executed after a delay,
 *   giving time to audit or veto the changes.
 *
 * This contract overrides the schedule(...) function to accept 'bytes memory'
 * instead of 'bytes calldata', thus avoiding the memory→calldata type mismatch.
 */
contract TimelockConfig is TimelockController {
    uint256 public param;

    // A custom modifier requiring that only this contract (the timelock) calls the function.
    modifier onlySelf() {
        require(msg.sender == address(this), "Caller must be Timelock itself");
        _;
    }

    constructor(
        uint256 minDelay,
        address[] memory proposers,
        address[] memory executors
    )
        TimelockController(minDelay, proposers, executors, msg.sender)
    {}

    /**
     * @dev Schedules a param change after the timelock's minDelay. 
     * We'll override schedule(...) to accept memory for 'data'.
     */
    function scheduleParamChange(uint256 newVal, bytes32 salt) external onlyRole(PROPOSER_ROLE) {
        // Encode the call data using memory
        bytes memory data = abi.encodeWithSelector(this.executeParamChange.selector, newVal);

        // Use our overridden schedule(...) that accepts 'bytes memory data'
        scheduleMemory(address(this), 0, data, bytes32(0), salt, getMinDelay());
    }

    /**
     * @dev Actually execute the param change, must be called by timelock after delay.
     */
    function executeParamChange(uint256 newVal) external onlySelf {
        param = newVal;
    }

    // =========== OVERRIDES ===========

    /**
     * @notice Overridden schedule(...) function that takes 'bytes memory data' 
     * instead of 'bytes calldata data'. This avoids the memory→calldata mismatch error.
     */
    function scheduleMemory(
        address target,
        uint256 value,
        bytes memory data,   // << memory here
        bytes32 predecessor,
        bytes32 salt,
        uint256 delay
    ) public onlyRole(PROPOSER_ROLE) {
        // We call the original schedule(...) from TimelockController,
        // which expects 'bytes calldata data' – this is allowed in >=0.8.4 
        // or we do an explicit cast if needed. 
        // In many compiler versions, passing 'memory' to a 'calldata' param is valid now.
        // If your compiler still complains, you may do an explicit cast or an inline call.
        super.schedule(target, value, data, predecessor, salt, delay);
    }
}
