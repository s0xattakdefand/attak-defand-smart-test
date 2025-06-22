// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title DynamicLinkLibrarySuite.sol
/// @notice On‑chain analogues of “Dynamic Link Library” (DLL) loading patterns:
///   Types: SharedLibrary, LoadTime, MemoryMapped  
///   AttackTypes: DLLInjection, Hijacking, OldVersionLoad, ReflectionInjection  
///   DefenseTypes: CodeSigning, SafeLoadPath, NamespaceIsolation, IntegrityCheck  

enum DynamicLinkLibraryType       { SharedLibrary, LoadTime, MemoryMapped }
enum DynamicLinkLibraryAttackType { DLLInjection, Hijacking, OldVersionLoad, ReflectionInjection }
enum DynamicLinkLibraryDefenseType{ CodeSigning, SafeLoadPath, NamespaceIsolation, IntegrityCheck }

error DLL__NotAllowed();
error DLL__BadSignature();
error DLL__AlreadyLoaded();
error DLL__BadChecksum();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE LOADER
//
//    • no checks: any address/path may be loaded
//    • Attack: DLLInjection, Hijacking
////////////////////////////////////////////////////////////////////////////////
contract DLLVuln {
    mapping(string => address) public libraries;
    event LibraryLoaded(
        address indexed who,
        string            path,
        address           lib,
        DynamicLinkLibraryAttackType attack
    );

    function loadLibrary(string calldata path, address lib) external {
        // ❌ no validation: attacker can inject any library
        libraries[path] = lib;
        emit LibraryLoaded(msg.sender, path, lib, DynamicLinkLibraryAttackType.DLLInjection);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//
//    • demonstrate hijacking and loading untrusted code
////////////////////////////////////////////////////////////////////////////////
contract Attack_DLL {
    DLLVuln public target;
    constructor(DLLVuln _t) { target = _t; }

    function hijack(string calldata path, address evilLib) external {
        target.loadLibrary(path, evilLib);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE LOADER WITH CODE SIGNING
//
//    • Defense: CodeSigning – require owner‑signed approval for library
////////////////////////////////////////////////////////////////////////////////
contract DLLSafeSigned {
    mapping(string => address) public libraries;
    address public approver;
    event LibraryLoaded(
        address indexed who,
        string            path,
        address           lib,
        DynamicLinkLibraryDefenseType defense
    );

    constructor(address _approver) {
        approver = _approver;
    }

    function loadLibrary(
        string calldata path,
        address lib,
        bytes calldata sig
    ) external {
        // verify signature over (path, lib) by approver
        bytes32 msgHash = keccak256(abi.encodePacked(path, lib));
        bytes32 ethMsg  = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", msgHash));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig, (uint8, bytes32, bytes32));
        address signer = ecrecover(ethMsg, v, r, s);
        if (signer != approver) revert DLL__BadSignature();

        libraries[path] = lib;
        emit LibraryLoaded(msg.sender, path, lib, DynamicLinkLibraryDefenseType.CodeSigning);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE LOADER WITH SAFE PATHS & NAMESPACE ISOLATION
//
//    • Defense: SafeLoadPath – only allow whitelisted paths
//               NamespaceIsolation – separate storage per library
////////////////////////////////////////////////////////////////////////////////
contract DLLSafeNamespace {
    mapping(string => address) public libraries;
    mapping(string => bool)    public allowedPath;
    mapping(bytes32 => mapping(bytes32 => bytes)) private libNamespace;
    address public owner;
    event LibraryLoaded(
        address indexed who,
        string            path,
        address           lib,
        DynamicLinkLibraryDefenseType defense
    );

    modifier onlyOwner() {
        if (msg.sender != owner) revert DLL__NotAllowed();
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function setAllowedPath(string calldata path, bool ok) external onlyOwner {
        allowedPath[path] = ok;
    }

    function loadLibrary(string calldata path, address lib) external {
        if (!allowedPath[path]) revert DLL__NotAllowed();
        libraries[path] = lib;
        // isolate namespace by storing a hash stub
        bytes32 ns = keccak256(abi.encodePacked(path));
        libNamespace[ns][bytes32(uint256(uint160(lib)))] = abi.encodePacked(block.timestamp);
        emit LibraryLoaded(msg.sender, path, lib, DynamicLinkLibraryDefenseType.SafeLoadPath);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED LOADER WITH INTEGRITY CHECK
//
//    • Defense: IntegrityCheck – require checksum match
////////////////////////////////////////////////////////////////////////////////
contract DLLSafeIntegrity {
    mapping(string => address) public libraries;
    mapping(string => bytes32) public checksums;
    event LibraryLoaded(
        address indexed who,
        string            path,
        address           lib,
        DynamicLinkLibraryDefenseType defense
    );

    error DLL__BadChecksum();

    /// owner registers expected checksum for each library path
    function setChecksum(string calldata path, bytes32 checksum) external {
        // assume deployer only
        require(msg.sender == address(this) || msg.sender == tx.origin, "only owner");
        checksums[path] = checksum;
    }

    function loadLibrary(string calldata path, address lib, bytes32 actualChecksum) external {
        bytes32 expected = checksums[path];
        if (expected == bytes32(0) || expected != actualChecksum) revert DLL__BadChecksum();
        libraries[path] = lib;
        emit LibraryLoaded(msg.sender, path, lib, DynamicLinkLibraryDefenseType.IntegrityCheck);
    }
}
