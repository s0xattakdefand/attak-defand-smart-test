interface ICommonSecurityControl {
    function hasRole(bytes32 role, address user) external view returns (bool);
    function isPaused() external view returns (bool);
}

contract Vault {
    ICommonSecurityControl public csc;

    bytes32 constant VAULT_ADMIN = keccak256("VAULT_ADMIN");

    constructor(address controlAddress) {
        csc = ICommonSecurityControl(controlAddress);
    }

    modifier onlyVaultAdmin() {
        require(csc.hasRole(VAULT_ADMIN, msg.sender), "Vault: Access denied");
        _;
    }

    modifier notPaused() {
        require(!csc.isPaused(), "Vault: Paused");
        _;
    }

    function withdraw(uint256 amount) external onlyVaultAdmin notPaused {
        // secure withdrawal logic
    }
}
