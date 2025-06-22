interface IRouterA {
    function forwardFromB(uint256 value) external;
}

contract RouterB {
    address public a;

    constructor(address _a) {
        a = _a;
    }

    function forwardFromA(uint256 value) external {
        require(value > 0, "Invalid");
        IRouterA(a).forwardFromB(value - 1);
    }
}
