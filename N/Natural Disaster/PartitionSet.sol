// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract PartitionSet {
    enum Region { GLOBAL, L1, L2, ZK }
    mapping(Region => bool) public partitioned;
    address public controller;

    constructor() {
        controller = msg.sender;
    }

    modifier onlyController() {
        require(msg.sender == controller, "Not authorized");
        _;
    }

    function setPartition(Region region, bool status) external onlyController {
        partitioned[region] = status;
    }

    function requireAvailable(Region region) external view {
        require(!partitioned[region], "Region is currently partitioned (RPC down)");
    }

    function isPartitioned(Region region) external view returns (bool) {
        return partitioned[region];
    }
}
