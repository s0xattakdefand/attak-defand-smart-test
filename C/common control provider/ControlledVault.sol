interface ICommonControlProvider {
    function hasRole(bytes32 role, address user) external view returns (bool);
    function isFlagEnabled(bytes32 flag) external view returns (bool);
}

contract ControlledVault {
    ICommonControlProvider public control;

    bytes32 constant GOV_ROLE = keccak256("GOVERNOR");
    bytes32 constant PAUSE_FLAG = keccak256("PAUSED");

    constructor(address controlProvider) {
        control = ICommonControlProvider(controlProvider);
    }

    modifier onlyGovernor() {
        require(control.hasRole(GOV_ROLE, msg.sender), "Vault: Not governor");
        _;
    }

    modifier notPaused() {
        require(!control.isFlagEnabled(PAUSE_FLAG), "Vault: Paused");
        _;
    }

    function withdraw() external onlyGovernor notPaused {
        // Withdraw logic
    }
}
