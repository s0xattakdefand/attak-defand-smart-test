// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/* =========================================================================
   SUPPLY-CHAIN DEMO — NIST Privacy Framework 1.0
   “The complex and interconnected relationships among entities involved in
    creating or deploying systems…”
   -------------------------------------------------------------------------
   · Section 1: UntrustedDataOrchestrator  (⚠️ vulnerable)
   · Section 2: RBACSupplyChain + MiniECDSA (helpers)
   · Section 3: SecureDataOrchestrator     (✅ hardened)
   ========================================================================= */

/// -------------------------------------------------------------------------
/// SECTION 1 — Vulnerable orchestrator that trusts unverified modules
/// -------------------------------------------------------------------------
contract UntrustedDataOrchestrator {
    mapping(uint256 => address[]) public pipelines;

    /// Anyone can point a pipeline at arbitrary module contracts.
    function createPipeline(uint256 id, address[] calldata modules) external {
        pipelines[id] = modules;
    }

    /// Data is run through each module via delegatecall (runs in this contract’s
    /// context!), so a malicious module can tamper with state or exfiltrate data.
    function process(uint256 id, bytes calldata data) external returns (bytes memory out) {
        address[] storage modules = pipelines[id];
        bytes memory current = data;
        for (uint256 i = 0; i < modules.length; i++) {
            (bool ok, bytes memory result) = modules[i].delegatecall(
                abi.encodeWithSignature("process(bytes)", current)
            );
            require(ok, "module failure");
            current = result;
        }
        out = current;
    }
}

/// -------------------------------------------------------------------------
/// SECTION 2 — Helpers for the hardened version
/// -------------------------------------------------------------------------
abstract contract RBACSupplyChain {
    bytes32 public constant ADMIN     = keccak256("ADMIN");
    bytes32 public constant DEVELOPER = keccak256("DEVELOPER");

    mapping(bytes32 => mapping(address => bool)) internal _roles;
    event RoleGranted(bytes32 indexed role, address indexed acct);
    event RoleRevoked(bytes32 indexed role, address indexed acct);

    modifier onlyRole(bytes32 role) {
        require(_roles[role][msg.sender], "Access denied");
        _;
    }

    constructor() {
        _grant(ADMIN, msg.sender);
    }

    function grantRole(bytes32 role, address acct) external onlyRole(ADMIN) {
        _grant(role, acct);
    }
    function revokeRole(bytes32 role, address acct) external onlyRole(ADMIN) {
        _revoke(role, acct);
    }
    function hasRole(bytes32 role, address acct) public view returns (bool) {
        return _roles[role][acct];
    }

    function _grant(bytes32 role, address acct) internal {
        if (!_roles[role][acct]) {
            _roles[role][acct] = true;
            emit RoleGranted(role, acct);
        }
    }
    function _revoke(bytes32 role, address acct) internal {
        if (_roles[role][acct]) {
            _roles[role][acct] = false;
            emit RoleRevoked(role, acct);
        }
    }
}

library MiniECDSA {
    function toEthSignedMessageHash(bytes32 hash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }
    function recover(bytes32 hash, bytes calldata sig) internal pure returns (address) {
        require(sig.length == 65, "Bad signature length");
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        return ecrecover(toEthSignedMessageHash(hash), v, r, s);
    }
}

/// Modules must implement this interface.
interface IDataModule {
    function process(bytes calldata data) external returns (bytes memory);
}

/// -------------------------------------------------------------------------
/// SECTION 3 — Hardened orchestrator with supply-chain governance
/// -------------------------------------------------------------------------
contract SecureDataOrchestrator is RBACSupplyChain {
    using MiniECDSA for bytes32;

    mapping(address => bool) public approvedModule;
    mapping(uint256 => address[]) public pipelines;

    event ModuleRegistered(address indexed module);
    event PipelineCreated(uint256 indexed id, address[] modules);

    /// Developers (with DEVELOPER role) sign the orchestrator’s address + module
    function registerModule(address moduleAddr, bytes calldata devSig) external {
        bytes32 hash = keccak256(abi.encodePacked(address(this), moduleAddr));
        address dev = hash.recover(devSig);
        require(hasRole(DEVELOPER, dev), "Unknown developer");
        approvedModule[moduleAddr] = true;
        emit ModuleRegistered(moduleAddr);
    }

    /// Only ADMIN may compose pipelines—and only from approved modules
    function createPipeline(uint256 id, address[] calldata modules) external onlyRole(ADMIN) {
        for (uint i = 0; i < modules.length; i++) {
            require(approvedModule[modules[i]], "Module not approved");
        }
        pipelines[id] = modules;
        emit PipelineCreated(id, modules);
    }

    /// Runs data through each module via external call (isolated), preventing
    /// module code from touching this contract’s storage.
    function process(uint256 id, bytes calldata data) external returns (bytes memory out) {
        address[] storage modules = pipelines[id];
        bytes memory current = data;
        for (uint256 i = 0; i < modules.length; i++) {
            (bool ok, bytes memory result) = modules[i].call(
                abi.encodeWithSelector(IDataModule.process.selector, current)
            );
            require(ok, "module failure");
            current = result;
        }
        out = current;
    }
}
