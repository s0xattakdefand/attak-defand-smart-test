// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title StraightThroughCableSuite.sol
/// @notice Analogues of a “straight‑through cable” in Solidity: unfiltered passthrough calls vs. hardened proxies.

error STC__NotAllowed();
error STC__TooManyForward();
error STC__NotWhitelisted();

////////////////////////////////////////////////////////////////////////
// 1) STRAIGHT‑THROUGH PROXY (VULNERABLE)
//    • Type: bare passthrough of ETH + calldata
//    • Attack: any caller can forward arbitrary calls (e.g. self‑destruct)
//    • Defense: see next modules
////////////////////////////////////////////////////////////////////////
contract StraightThroughCableVuln {
    event Forwarded(address indexed caller, address indexed to, uint256 value, bytes data);

    /// ❌ no filtering or access control
    function cableCall(address to, bytes calldata data) external payable {
        (bool ok, ) = to.call{value: msg.value}(data);
        require(ok, "call failed");
        emit Forwarded(msg.sender, to, msg.value, data);
    }
}

////////////////////////////////////////////////////////////////////////
// 2) DEMONSTRATION ATTACK
//    Uses the vulnerable proxy to hijack/destruct its own code.
////////////////////////////////////////////////////////////////////////
contract Attack_StraightThroughCable {
    StraightThroughCableVuln public proxy;
    constructor(StraightThroughCableVuln _proxy) { proxy = _proxy; }

    /// Call proxy to self‑destruct it, sending all ETH to attacker
    function hijack() external {
        // encode selfdestruct(msg.sender)
        bytes memory payload = abi.encodeWithSignature("selfdestruct(address)", msg.sender);
        proxy.cableCall(address(proxy), payload);
    }
}

////////////////////////////////////////////////////////////////////////
// 3) ACCESS‑CONTROLLED PROXY (SAFE)
//    • Type: whitelist targets + restrict to owner
//    • Defense: only owner may forward, and only to approved addresses
////////////////////////////////////////////////////////////////////////
contract StraightThroughCableSafe {
    address public owner;
    mapping(address => bool) public whitelisted;
    event Forwarded(address indexed caller, address indexed to, uint256 value, bytes data);
    event WhitelistUpdated(address indexed target, bool allowed);

    constructor() {
        owner = msg.sender;
    }

    /// ✅ owner may toggle which addresses can be called
    function setWhitelist(address target, bool ok) external {
        if (msg.sender != owner) revert STC__NotAllowed();
        whitelisted[target] = ok;
        emit WhitelistUpdated(target, ok);
    }

    /// ✅ only owner may call, and only to whitelisted targets
    function cableCall(address to, bytes calldata data) external payable {
        if (msg.sender != owner)            revert STC__NotAllowed();
        if (!whitelisted[to])               revert STC__NotWhitelisted();
        (bool ok, ) = to.call{value: msg.value}(data);
        require(ok, "call failed");
        emit Forwarded(msg.sender, to, msg.value, data);
    }
}

////////////////////////////////////////////////////////////////////////
// 4) RATE‑LIMITED PROXY (ENHANCED SAFE)
//    • Type: throttle number of forwards per sender to prevent abuse
//    • Defense: per‑sender counter + cap
////////////////////////////////////////////////////////////////////////
contract StraightThroughCableSafeRateLimited {
    address public owner;
    mapping(address => bool) public whitelisted;
    mapping(address => uint256) public forwardCount;
    uint256 public constant MAX_FORWARD = 10;

    error STC__RateLimit();

    event Forwarded(address indexed caller, address indexed to, uint256 value, bytes data);
    event WhitelistUpdated(address indexed target, bool allowed);

    constructor() {
        owner = msg.sender;
    }

    /// owner may whitelist targets
    function setWhitelist(address target, bool ok) external {
        if (msg.sender != owner) revert STC__NotAllowed();
        whitelisted[target] = ok;
        emit WhitelistUpdated(target, ok);
    }

    /// only whitelisted targets, and throttle per‑caller
    function cableCall(address to, bytes calldata data) external payable {
        if (!whitelisted[to]) revert STC__NotWhitelisted();
        uint256 count = forwardCount[msg.sender] + 1;
        if (count > MAX_FORWARD) revert STC__TooManyForward();
        forwardCount[msg.sender] = count;

        (bool ok, ) = to.call{value: msg.value}(data);
        require(ok, "call failed");
        emit Forwarded(msg.sender, to, msg.value, data);
    }
}
