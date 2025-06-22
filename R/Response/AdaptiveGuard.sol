contract AdaptiveGuard is IResponseStrategy {
    mapping(bytes4 => bool) public blacklisted;
    mapping(address => bool) public frozen;

    event SelectorBlocked(bytes4);
    event AddressFrozen(address);

    function respond(bytes4 selector, address origin, string calldata hint) external override {
        if (keccak256(bytes(hint)) == keccak256("zero-day")) {
            blacklisted[selector] = true;
            emit SelectorBlocked(selector);
        }

        if (keccak256(bytes(hint)) == keccak256("reentry")) {
            frozen[origin] = true;
            emit AddressFrozen(origin);
        }
    }

    modifier protect(bytes4 selector) {
        require(!blacklisted[selector], "Blocked selector");
        require(!frozen[msg.sender], "Sender frozen");
        _;
    }
}
