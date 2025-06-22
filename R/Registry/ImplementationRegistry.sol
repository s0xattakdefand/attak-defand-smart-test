contract ImplementationRegistry {
    mapping(bytes32 => address) public versionToLogic;
    event LogicRegistered(bytes32 hash, address logic);

    function register(bytes32 hash, address logic) external {
        versionToLogic[hash] = logic;
        emit LogicRegistered(hash, logic);
    }
}
