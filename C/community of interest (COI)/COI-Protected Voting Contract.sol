interface ICOIRegistry {
    function isMember(address user) external view returns (bool);
}

contract COIVoting {
    ICOIRegistry public registry;

    constructor(address registryAddress) {
        registry = ICOIRegistry(registryAddress);
    }

    function vote(uint256 proposalId) external {
        require(registry.isMember(msg.sender), "Not part of this COI");
        // Proceed with COI-only vote
    }
}
