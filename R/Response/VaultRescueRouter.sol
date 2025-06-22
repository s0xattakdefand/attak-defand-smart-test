interface ISafeVault {
    function rescueFunds(address token) external;
}

contract VaultRescueRouter {
    ISafeVault public safe;

    constructor(address _vault) {
        safe = ISafeVault(_vault);
    }

    function trigger(address token) external {
        safe.rescueFunds(token);
    }
}
