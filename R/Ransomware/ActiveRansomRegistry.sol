contract ActiveRansomRegistry {
    struct RansomData {
        address contractAddr;
        uint256 deadline;
        uint256 ransomAmount;
        bool active;
    }

    RansomData[] public activeRansoms;
    event RansomRegistered(address addr, uint256 ransom, uint256 deadline);

    function register(address addr, uint256 ransom, uint256 deadline) external {
        activeRansoms.push(RansomData(addr, deadline, ransom, true));
        emit RansomRegistered(addr, ransom, deadline);
    }

    function list() external view returns (RansomData[] memory) {
        return activeRansoms;
    }
}
