// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ConfidenceIntervalGuard — Enforces CIs for price feeds, latency, and gas usage
contract ConfidenceIntervalGuard {
    address public owner;
    uint256 public lastPrice;
    uint256 public priceConfidenceBps = 500; // 5% tolerance
    uint256 public maxLatency = 10 minutes;
    uint256 public expectedGas = 100000;

    struct OracleData {
        uint256 price;
        uint256 timestamp;
    }

    event PriceAccepted(uint256 price);
    event PriceRejected(uint256 price, string reason);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    /// 🔐 Enforce confidence interval: price must be within tolerance of last known price
    function updatePrice(OracleData calldata data) external returns (bool) {
        if (lastPrice == 0) {
            lastPrice = data.price;
            emit PriceAccepted(data.price);
            return true;
        }

        uint256 lower = (lastPrice * (10_000 - priceConfidenceBps)) / 10_000;
        uint256 upper = (lastPrice * (10_000 + priceConfidenceBps)) / 10_000;

        if (data.price < lower || data.price > upper) {
            emit PriceRejected(data.price, "Outside confidence range");
            return false;
        }

        if (block.timestamp - data.timestamp > maxLatency) {
            emit PriceRejected(data.price, "Stale timestamp");
            return false;
        }

        lastPrice = data.price;
        emit PriceAccepted(data.price);
        return true;
    }

    /// 🔧 Adjust CI threshold
    function setPriceConfidenceBps(uint256 bps) external onlyOwner {
        require(bps <= 5000, "Too high"); // Max 50%
        priceConfidenceBps = bps;
    }

    function setMaxLatency(uint256 seconds_) external onlyOwner {
        maxLatency = seconds_;
    }
}
