contract LegacyVault {
    uint256 public totalDeposits;
    address public admin;
}

contract ZeroDayNewLogic is LegacyVault {
    event OwnershipChanged(address newOwner);

    function initOwner(address newOwner) external {
        admin = newOwner;
        emit OwnershipChanged(newOwner);
    }
}
