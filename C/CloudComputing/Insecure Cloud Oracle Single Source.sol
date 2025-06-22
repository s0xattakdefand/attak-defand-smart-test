// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * A naive oracle relying on a single cloud-based server
 * Attack: If that server is compromised, it can feed false data
 */
contract NaiveCloudOracle {
    address public cloudServer; // single address controlling data
    uint256 public price;

    constructor(address server) {
        cloudServer = server;
    }

    function updatePrice(uint256 newPrice) external {
        // ❌ only one address can set the price, no validation
        require(msg.sender == cloudServer, "Not the cloud server");
        price = newPrice;
    }
}
