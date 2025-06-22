// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// AISRegistry — Automated Indicator Sharing for decentralized threat intelligence
contract AISRegistry {
    address public admin;

    struct Indicator {
        address source;
        string category;        // e.g., "selector_drift", "zk_replay", "reentrancy"
        bytes32 indicatorHash;  // keccak256 of threat vector
        uint256 severity;       // 1 = low, 5 = critical
        string uri;             // Optional metadata pointer (IPFS, Arweave)
        uint256 timestamp;
    }

    Indicator[] public indicators;

    event IndicatorShared(uint256 indexed id, address indexed source, string category, bytes32 hash, uint256 severity);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function shareIndicator(
        string calldata category,
        bytes32 indicatorHash,
        uint256 severity,
        string calldata uri
    ) external onlyAdmin returns (uint256) {
        indicators.push(Indicator(msg.sender, category, indicatorHash, severity, uri, block.timestamp));
        uint256 id = indicators.length - 1;
        emit IndicatorShared(id, msg.sender, category, indicatorHash, severity);
        return id;
    }

    function getIndicator(uint256 id) external view returns (Indicator memory) {
        return indicators[id];
    }

    function totalIndicators() external view returns (uint256) {
        return indicators.length;
    }
}
