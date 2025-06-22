// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

interface IDefenseUplink {
    function pushEvent(string calldata label, bytes4 selector, address source) external;
}

contract RiskAverseGuard {
    mapping(address => bool) public whitelist;
    mapping(bytes4 => bool) public selectorAllowlist;
    mapping(bytes32 => bool) public replaySeen;

    IDefenseUplink public uplink;
    address public delegate;
    uint8 public maxEntropy = 6;
    uint256 public failCount;
    bool public paused;

    constructor(address _delegate, address _uplink) {
        delegate = _delegate;
        uplink = IDefenseUplink(_uplink);
    }

    // === ENTROPY CHECK ===
    function selectorEntropy(bytes4 sel) public pure returns (uint8 e) {
        uint32 x = uint32(sel);
        while (x != 0) { e++; x &= (x - 1); }
    }

    modifier defense(bytes4 sel) {
        require(!paused, "Paused");

        if (!whitelist[msg.sender]) revert("Not whitelisted");
        if (!selectorAllowlist[sel]) revert("Selector not allowed");

        bytes32 sigHash = keccak256(msg.data);
        require(!replaySeen[sigHash], "Replay");
        replaySeen[sigHash] = true;

        uint8 entropy = selectorEntropy(sel);
        if (entropy > maxEntropy) {
            uplink.pushEvent("entropy_violation", sel, msg.sender);
            failCount++;
            if (failCount >= 3) paused = true;
        }
        _;
    }

    function execute(bytes calldata callData) external defense(bytes4(callData[:4])) {
        (bool ok, bytes memory out) = delegate.delegatecall(callData);
        require(ok, "Execution failed");
        assembly { return(add(out, 32), mload(out)) }
    }

    // === ADMIN ===
    function allow(address user) external { whitelist[user] = true; }
    function approveSelector(bytes4 sig) external { selectorAllowlist[sig] = true; }
    function adjustEntropy(uint8 limit) external { maxEntropy = limit; }
    function reset() external { failCount = 0; paused = false; }
}
