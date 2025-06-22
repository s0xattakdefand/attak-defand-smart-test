contract TimeRiskAnalyzer {
    mapping(address => uint256) public lastActionBlock;

    function riskyAction() external {
        require(block.number > lastActionBlock[msg.sender], "Drift exploit risk");
        lastActionBlock[msg.sender] = block.number;
    }
}
