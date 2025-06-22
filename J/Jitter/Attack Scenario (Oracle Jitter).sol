pragma solidity ^0.8.21;

interface PriceFeed {
    function latestPrice() external view returns (uint256);
}

contract OracleJitterExploit {
    PriceFeed public feed;

    constructor(address _feed) {
        feed = PriceFeed(_feed);
    }

    function buyAsset() external payable {
        require(msg.value > 0);
        uint256 delayedPrice = feed.latestPrice(); // may be stale!
        // exploit logic: get asset for old (cheaper) price
    }
}
