// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/Counters.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/**
 * DEFENSE TYPE:
 * A contract that issues ephemeral port-like IDs using a secure incremental or random approach. 
 * Doesn’t allow user-chosen ephemeral IDs => no collisions or guess attacks.
 */
contract SecureEphemeralPort {
    using Counters for Counters.Counter;
    Counters.Counter private _sessionCounter;

    // ephemeral session => user
    mapping(uint256 => address) public ephemeralOwner;

    event EphemeralAllocated(uint256 ephemeralID, address owner);

    /**
     * @dev The contract picks ephemeral IDs sequentially or from VRF,
     * not the user. Minimizes collision/hijack risk.
     */
    function createEphemeral() external {
        _sessionCounter.increment();
        uint256 newID = _sessionCounter.current();
        ephemeralOwner[newID] = msg.sender;
        emit EphemeralAllocated(newID, msg.sender);
    }

    /**
     * @dev Example usage: check ephemeral ID ownership
     */
    function isOwnerOf(uint256 ephemeralID, address user) external view returns (bool) {
        return ephemeralOwner[ephemeralID] == user;
    }
}
