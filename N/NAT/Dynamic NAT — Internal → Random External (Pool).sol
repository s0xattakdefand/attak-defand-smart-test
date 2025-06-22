contract DynamicNAT {
    address[] public natPool;
    mapping(address => address) public assignments;

    constructor(address[] memory pool) {
        natPool = pool;
    }

    function assign(address internalAddr) external {
        require(assignments[internalAddr] == address(0), "Already assigned");
        uint256 i = uint256(keccak256(abi.encodePacked(block.timestamp, internalAddr))) % natPool.length;
        assignments[internalAddr] = natPool[i];
    }

    function resolve(address internalAddr) external view returns (address) {
        return assignments[internalAddr];
    }
}
