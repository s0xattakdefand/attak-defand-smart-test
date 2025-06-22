contract Vault {
    RSBACGuard public rsbac;

    constructor(address _rsbac) {
        rsbac = RSBACGuard(_rsbac);
    }

    function sensitiveTransfer(address to, uint256 amount) external rsbac.onlyAllowed {
        // critical logic
    }
}
