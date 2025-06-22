// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title SymbolicLinkSuite.sol
/// @notice On‑chain analogues of four “symbolic link” patterns:
///   1) Unrestricted Link Creation  
///   2) Dangling Link  
///   3) TOCTOU Link Follow  
///   4) Cyclic Link Detection  

error SL__NotOwner();
error SL__BadTarget();
error SL__LoopDetected();
error SL__DepthExceeded();

////////////////////////////////////////////////////////////////////////
// 1) UNRESTRICTED LINK CREATION
//    • Vulnerable: anyone can create or override any link
//    • Attack: attacker repoints victim’s path to malicious contract
//    • Defense: only owner may create/override links
////////////////////////////////////////////////////////////////////////
contract SymlinkRegistryVuln {
    mapping(string => address) public targetOf;
    event LinkSet(string path, address target);

    function setLink(string calldata path, address target) external {
        // ❌ unrestricted
        targetOf[path] = target;
        emit LinkSet(path, target);
    }

    function resolve(string calldata path) external view returns (address) {
        return targetOf[path];
    }
}

contract Attack_SymlinkOverride {
    SymlinkRegistryVuln public reg;
    constructor(SymlinkRegistryVuln _r) { reg = _r; }
    function hijack(string calldata victimPath, address evil) external {
        // repoint victim’s path
        reg.setLink(victimPath, evil);
    }
}

contract SymlinkRegistrySafe {
    mapping(string => address) private _targetOf;
    address public immutable owner;
    event LinkSet(string path, address target);

    constructor() { owner = msg.sender; }

    function setLink(string calldata path, address target) external {
        if (msg.sender != owner) revert SL__NotOwner();
        _targetOf[path] = target;
        emit LinkSet(path, target);
    }

    function resolve(string calldata path) external view returns (address) {
        return _targetOf[path];
    }
}

////////////////////////////////////////////////////////////////////////
// 2) DANGLING LINK
//    • Vulnerable: allows links to non‑contract addresses → follow fails
//    • Attack: create link to EOA or zero address, follow → revert
//    • Defense: require linked address has code
////////////////////////////////////////////////////////////////////////
contract DanglingSymlinkVuln {
    mapping(string => address) public targetOf;

    function setLink(string calldata path, address target) external {
        targetOf[path] = target;
    }

    function follow(string calldata path, bytes calldata data) external returns (bytes memory) {
        address tgt = targetOf[path];
        // ❌ may be non‑contract or zero → call will revert or no code
        (bool ok, bytes memory ret) = tgt.call(data);
        require(ok, "call failed");
        return ret;
    }
}

contract Attack_DanglingSymlink {
    DanglingSymlinkVuln public reg;
    constructor(DanglingSymlinkVuln _r) { reg = _r; }

    function exploit(string calldata path) external {
        // follow a dangling link → revert
        reg.follow(path, "");
    }
}

contract DanglingSymlinkSafe {
    mapping(string => address) private _targetOf;
    event LinkSet(string path, address target);

    function setLink(string calldata path, address target) external {
        // ✅ require target is a contract
        uint32 size;
        assembly { size := extcodesize(target) }
        if (size == 0) revert SL__BadTarget();
        _targetOf[path] = target;
        emit LinkSet(path, target);
    }

    function follow(string calldata path, bytes calldata data) external returns (bytes memory) {
        address tgt = _targetOf[path];
        (bool ok, bytes memory ret) = tgt.call(data);
        require(ok, "call failed");
        return ret;
    }
}

////////////////////////////////////////////////////////////////////////
// 3) TOCTOU LINK FOLLOW
//    • Vulnerable: resolve & follow in two steps → attacker races update
//    • Attack: between resolve() and follow(), attacker swaps link
//    • Defense: atomic resolve+call in single function
////////////////////////////////////////////////////////////////////////
contract TOCTOUVuln {
    mapping(string => address) public targetOf;

    function setLink(string calldata path, address target) external {
        targetOf[path] = target;
    }

    function resolve(string calldata path) external view returns (address) {
        return targetOf[path];
    }
    function follow(string calldata path, bytes calldata data) external returns (bytes memory) {
        address tgt = targetOf[path];
        (bool ok, bytes memory ret) = tgt.call(data);
        require(ok, "call failed");
        return ret;
    }
}

contract Attack_TOCTOU {
    TOCTOUVuln public reg;
    constructor(TOCTOUVuln _r) { reg = _r; }

    function hijack(string calldata path, address evil) external {
        // between off‑chain resolve and on‑chain follow, call setLink:
        reg.setLink(path, evil);
    }
}

contract TOCTOUSafe {
    mapping(string => address) private _targetOf;

    function setLink(string calldata path, address target) external {
        _targetOf[path] = target;
    }

    /// ✅ atomic resolve + call prevents TOCTOU
    function atomicFollow(string calldata path, bytes calldata data) external returns (bytes memory) {
        address tgt = _targetOf[path];
        (bool ok, bytes memory ret) = tgt.call(data);
        require(ok, "call failed");
        return ret;
    }
}

////////////////////////////////////////////////////////////////////////
// 4) CYCLIC LINK DETECTION
//    • Vulnerable: following symlinks in a loop → infinite recursion
//    • Attack: create A→B, B→A and call followChain
//    • Defense: detect loops via depth or seen map
////////////////////////////////////////////////////////////////////////
contract CyclicSymlinkVuln {
    mapping(string => string) public linkOf;

    function setLink(string calldata path, string calldata to) external {
        linkOf[path] = to;
    }

    function followChain(string calldata start, bytes calldata data) external returns (bytes memory) {
        // naive recursion: may loop forever
        string memory p = start;
        while (true) {
            address tgt = resolve(p);
            if (tgt != address(0)) {
                (bool ok, bytes memory ret) = tgt.call(data);
                require(ok, "call failed");
                return ret;
            }
            p = linkOf[p];
        }
    }

    function resolve(string memory p) internal view returns (address) {
        // assume resolution if path maps to contract address via some naming
        // stubbed as zero
        return address(0);
    }
}

contract Attack_CyclicSymlink {
    CyclicSymlinkVuln public reg;
    constructor(CyclicSymlinkVuln _r) { reg = _r; }

    function loop(string calldata a, string calldata b) external {
        reg.setLink(a, b);
        reg.setLink(b, a);
        // calling followChain(a,...) will never terminate
        reg.followChain(a, "");
    }
}

contract CyclicSymlinkSafe {
    mapping(string => string) private _linkOf;

    function setLink(string calldata path, string calldata to) external {
        _linkOf[path] = to;
    }

    /// ✅ Detect cycles up to `maxDepth`
    function followChainSafe(
        string calldata start,
        bytes calldata data,
        uint256 maxDepth
    ) external returns (bytes memory) {
        string memory p = start;
        for (uint i = 0; i < maxDepth; i++) {
            address tgt = resolve(p);
            if (tgt != address(0)) {
                (bool ok, bytes memory ret) = tgt.call(data);
                require(ok, "call failed");
                return ret;
            }
            p = _linkOf[p];
        }
        revert SL__LoopDetected();
    }

    function resolve(string memory) internal pure returns (address) {
        // stub: always zero
        return address(0);
    }
}
