interface ISelectorRegistry {
    function registered(bytes4) external view returns (bool);
}

contract AutoReplayFiltered {
    ISelectorRegistry public registry;

    constructor(address _reg) {
        registry = ISelectorRegistry(_reg);
    }

    function replay(address target, bytes4[] calldata selectors) external {
        for (uint256 i = 0; i < selectors.length; i++) {
            if (registry.registered(selectors[i])) {
                (bool ok, ) = target.call(abi.encodePacked(selectors[i]));
                // log if needed
            }
        }
    }
}
