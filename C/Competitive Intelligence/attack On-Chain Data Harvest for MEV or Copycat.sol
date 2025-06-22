// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * Attack scenario: 
 * A naive aggregator that scrapes competitor's on-chain data (ex. liquidity, user count),
 * then uses it to front-run or replicate competitor strategies.
 */
contract CompetitorScraper {
    // For demonstration, we store competitor's top deposit amounts
    address public competitorContract;

    // Aggregated data from competitor
    mapping(uint256 => address) public topDepositors;
    uint256 public lastIndex;

    constructor(address _competitor) {
        competitorContract = _competitor;
    }

    /**
     * @dev 'Scrape' competitor deposit info.
     * - In real usage, this might read competitor's public state, 
     *   e.g. an array or mapping of user deposits.
     */
    function scrapeData(address[] calldata depositors) external {
        // Attack: just read competitor data 
        // (Pretend competitorContract has a public `getDeposit` function)
        for (uint256 i = 0; i < depositors.length; i++) {
            // read competitor deposit
            // e.g. (bool success, bytes memory result) = competitorContract.staticcall(...);
            // but we'll store depositors as if we gleaned intelligence
            topDepositors[lastIndex] = depositors[i];
            lastIndex++;
        }
    }
}
