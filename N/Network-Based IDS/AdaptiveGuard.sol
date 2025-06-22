contract AdaptiveGuard {
    mapping(bytes4 => bool) public blockedSelectors;

    event BlockedSelector(bytes4 selector);
    event AllowedCall(address caller, bytes4 selector);

    function blockSelector(bytes4 selector) external {
        blockedSelectors[selector] = true;
        emit BlockedSelector(selector);
    }

    fallback() external payable {
        bytes4 sel;
        assembly { sel := calldataload(0) }

        require(!blockedSelectors[sel], "Blocked selector");
        emit AllowedCall(msg.sender, sel);
        // You could forward or delegatecall here if needed
    }
}
