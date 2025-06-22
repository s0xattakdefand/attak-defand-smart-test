// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/Counters.sol";

contract TimeBasedEphemeral {
    using Counters for Counters.Counter;
    Counters.Counter private _idCounter;

    struct EphemeralData {
        address owner;
        uint256 expireAt;
    }

    mapping(uint256 => EphemeralData) public ephemeralSlots;

    function createEphemeral(uint256 ttlSeconds) external {
        _idCounter.increment();
        uint256 newID = _idCounter.current();
        ephemeralSlots[newID] = EphemeralData({
            owner: msg.sender,
            expireAt: block.timestamp + ttlSeconds
        });
    }

    function isActive(uint256 ephemeralID) public view returns (bool) {
        return block.timestamp <= ephemeralSlots[ephemeralID].expireAt;
    }

    // attacker can't forcibly reuse ID if it hasn't expired
}
