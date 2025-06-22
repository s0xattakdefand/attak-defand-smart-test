contract OracleGapExploit {
    uint256 public price;

    function updatePrice(uint256 p) external {
        price = p;
    }

    function buyWithPriceRace() external payable {
        require(price < 100 ether, "Too expensive");
        // attacker updates price here via separate tx before execution finishes
        // classic storage race between reads & external update
    }
}
