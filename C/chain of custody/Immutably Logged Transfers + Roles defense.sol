// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * A chain-of-custody approach:
 * - Must have the item in your custody to transfer it
 * - Transfers emit events to form an immutable log
 * - Optional signature or role checks
 */
contract CustodyChain {
    mapping(bytes32 => address) public currentHolder;
    // For each item, we keep an array of custody events (addresses + timestamp)
    mapping(bytes32 => address[]) public custodyTrail;

    event CustodyTransferred(bytes32 indexed itemId, address from, address to, uint256 timestamp);

    // Initialize item with an original holder
    function initializeCustody(bytes32 itemId, address initialHolder) external {
        require(currentHolder[itemId] == address(0), "Already initialized");
        currentHolder[itemId] = initialHolder;
        custodyTrail[itemId].push(initialHolder);
        emit CustodyTransferred(itemId, address(0), initialHolder, block.timestamp);
    }

    // Transfer custody from current holder to new holder
    function transferCustody(bytes32 itemId, address newHolder) external {
        require(currentHolder[itemId] == msg.sender, "Not item holder");
        address oldHolder = currentHolder[itemId];
        currentHolder[itemId] = newHolder;
        custodyTrail[itemId].push(newHolder);
        emit CustodyTransferred(itemId, oldHolder, newHolder, block.timestamp);
    }

    // Retrieve the entire chain of custody for an item
    function getCustodyTrail(bytes32 itemId) external view returns (address[] memory) {
        return custodyTrail[itemId];
    }
}
