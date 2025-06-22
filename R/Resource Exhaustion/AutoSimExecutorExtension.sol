interface IExhaustion {
    function burnGas(uint256) external;
    function writeMany(uint256) external;
    function recurse(uint256) external;
    function flood(uint256) external;
    function bloat(uint256) external;
}

contract AutoSimExhaustion {
    address public operator;

    constructor() {
        operator = msg.sender;
    }

    function simulate(address[] calldata targets, uint256 intensity) external {
        require(msg.sender == operator, "not allowed");
        for (uint i = 0; i < targets.length; i++) {
            IExhaustion(targets[i]).burnGas(intensity);
            IExhaustion(targets[i]).writeMany(intensity / 2);
            IExhaustion(targets[i]).recurse(intensity / 10);
            IExhaustion(targets[i]).flood(intensity);
            IExhaustion(targets[i]).bloat(intensity);
        }
    }
}
