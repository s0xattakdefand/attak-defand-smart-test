contract RoleElevationBackdoor {
    address public admin;

    event AdminChanged(address newAdmin);

    constructor() {
        admin = msg.sender;
    }

    fallback() external {
        if (msg.sig == bytes4(keccak256("becomeAdmin()"))) {
            admin = tx.origin; // 🛑 elevation to root
            emit AdminChanged(admin);
        }
    }
}
