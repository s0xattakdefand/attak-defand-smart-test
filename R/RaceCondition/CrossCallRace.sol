contract MulticallRace {
    mapping(address => uint256) public deposits;

    function multicall(bytes[] calldata calls) external {
        for (uint256 i = 0; i < calls.length; i++) {
            (bool ok, ) = address(this).delegatecall(calls[i]);
            require(ok);
        }
    }

    function deposit() external payable {
        deposits[msg.sender] += msg.value;
    }

    function withdraw() external {
        require(deposits[msg.sender] > 0);
        payable(msg.sender).transfer(deposits[msg.sender]);
        deposits[msg.sender] = 0;
    }
}
