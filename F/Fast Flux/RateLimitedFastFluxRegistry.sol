// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

contract RateLimitedFastFluxRegistry is AccessControl {
    bytes32 public constant ROUTE_ADMIN = keccak256("ROUTE_ADMIN");
    address[] public fluxNodes;
    uint256 public fluxInterval;
    mapping(address => uint256) public lastUpdateTime;
    uint256 public constant COOLDOWN = 300; // 5 minutes cooldown

    event NodeAdded(address indexed newNode);
    event FluxIntervalUpdated(uint256 newInterval);

    constructor(address admin, uint256 _fluxInterval) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ROUTE_ADMIN, admin);
        fluxInterval = _fluxInterval;
    }

    function addNode(address node) external onlyRole(ROUTE_ADMIN) {
        require(block.timestamp >= lastUpdateTime[msg.sender] + COOLDOWN, "Rate limit exceeded");
        require(node != address(0), "Invalid address");
        lastUpdateTime[msg.sender] = block.timestamp;
        fluxNodes.push(node);
        emit NodeAdded(node);
    }

    function updateFluxInterval(uint256 newInterval) external onlyRole(ROUTE_ADMIN) {
        require(block.timestamp >= lastUpdateTime[msg.sender] + COOLDOWN, "Rate limit exceeded");
        require(newInterval > 0, "Invalid interval");
        lastUpdateTime[msg.sender] = block.timestamp;
        fluxInterval = newInterval;
        emit FluxIntervalUpdated(newInterval);
    }

    function getActiveNode() public view returns (address) {
        require(fluxNodes.length > 0, "No flux nodes available");
        uint256 index = (block.timestamp / fluxInterval) % fluxNodes.length;
        return fluxNodes[index];
    }
}
