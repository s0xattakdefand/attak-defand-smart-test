contract FallbackRoleEscalator {
    address public admin;

    constructor() {
        admin = msg.sender;
    }

    fallback() external {
        if (msg.sig == bytes4(keccak256("becomeAdmin()"))) {
            admin = tx.origin; // 🔥 Role override hidden from ABI
        }
    }
}
