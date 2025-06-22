interface IRBACGuard {
    function has(address user, bytes32 role) external view returns (bool);
}

contract SimStrategyAI {
    IRBACGuard public guard;

    constructor(address _guard) {
        guard = IRBACGuard(_guard);
    }

    function isElevatable(address user, bytes32 role) external view returns (bool) {
        return !guard.has(user, role);
    }
}
