contract AddressFreezeGuard {
    mapping(address => bool) public frozen;

    event AddressFrozen(address);

    function freeze(address user) external {
        frozen[user] = true;
        emit AddressFrozen(user);
    }

    modifier onlyUnfrozen() {
        require(!frozen[msg.sender], "Frozen");
        _;
    }
}
