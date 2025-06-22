// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * Another approach: Extended ACL using a Timelock + role checks. 
 * No direct calls allowed unless scheduled, ensuring multi-condition flows.
 */
import "@openzeppelin/contracts/governance/TimelockController.sol";

contract TimelockExtendedACL is TimelockController {
    constructor(
        uint256 minDelay,
        address[] memory proposers,
        address[] memory executors
    )
        TimelockController(minDelay, proposers, executors, msg.sender)
    {}
    
    // Proposed changes must wait 'minDelay' seconds,
    // and only addresses with PROPOSER_ROLE can schedule them,
    // while executors must have EXECUTOR_ROLE. 
    // => Very extended ACL approach.
}
