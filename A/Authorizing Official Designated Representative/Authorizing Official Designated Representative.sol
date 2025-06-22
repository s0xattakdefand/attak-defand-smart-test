// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract AODRDelegation {
    struct Delegate {
        address addr;
        bytes4[] allowedSelectors;
        uint256 expiresAt;
        bool active;
    }

    mapping(address => Delegate) public delegates; // AO → Delegate

    event DelegateAssigned(address indexed ao, address indexed delegate, uint256 expiresAt);
    event DelegateRevoked(address indexed ao);
    event ActionExecuted(address indexed delegate, address ao, bytes4 selector);

    modifier onlyDelegate(address ao, bytes4 selector) {
        Delegate memory d = delegates[ao];
        require(d.active, "No active delegate");
        require(block.timestamp <= d.expiresAt, "Delegate expired");
        require(msg.sender == d.addr, "Not authorized delegate");

        bool allowed = false;
        for (uint i = 0; i < d.allowedSelectors.length; i++) {
            if (d.allowedSelectors[i] == selector) {
                allowed = true;
                break;
            }
        }
        require(allowed, "Selector not allowed");
        _;
    }

    function assignDelegate(
        address ao,
        address delegateAddr,
        bytes4[] calldata selectors,
        uint256 expiresIn
    ) external {
        require(msg.sender == ao, "Only AO can assign");
        delegates[ao] = Delegate({
            addr: delegateAddr,
            allowedSelectors: selectors,
            expiresAt: block.timestamp + expiresIn,
            active: true
        });
        emit DelegateAssigned(ao, delegateAddr, block.timestamp + expiresIn);
    }

    function revokeDelegate(address ao) external {
        require(msg.sender == ao, "Only AO can revoke");
        delegates[ao].active = false;
        emit DelegateRevoked(ao);
    }

    function actAsAO(address ao, bytes4 selector) external onlyDelegate(ao, selector) {
        emit ActionExecuted(msg.sender, ao, selector);
        // Integrate this logic with actual governance router, metaTx forwarder, etc.
    }

    function getDelegateInfo(address ao) external view returns (Delegate memory) {
        return delegates[ao];
    }
}
