contract Vulnerable {
    address public owner;

    constructor() {
        owner = tx.origin; // ❌ Vulnerable
    }

    function sensitiveAction() external {
        require(tx.origin == owner, "Not authorized");
    }
}
