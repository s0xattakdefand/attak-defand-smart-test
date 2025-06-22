// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/* ================== PATCH TYPES ================== */

// 1️⃣ Proxy Delegate Patch
contract PatchProxy {
    address public logic;

    function upgrade(address newLogic) external {
        logic = newLogic;
    }

    fallback() external payable {
        address _impl = logic;
        require(_impl != address(0), "Logic not set");
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), _impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result case 0 { revert(0, returndatasize()) } default { return(0, returndatasize()) }
        }
    }
}

// 2️⃣ Hotfix Role Patch
contract HotfixAdminPatch {
    address public admin;
    string public patchedResult;

    modifier onlyAdmin() {
        require(msg.sender == admin, "Denied");
        _;
    }

    function patch(string calldata msgTxt) external onlyAdmin {
        patchedResult = msgTxt;
    }
}

// 3️⃣ Selector Reroute Patch
contract SelectorReroute {
    mapping(bytes4 => address) public patchedRoute;

    function patchSelector(bytes4 selector, address target) external {
        patchedRoute[selector] = target;
    }

    fallback() external {
        address r = patchedRoute[msg.sig];
        require(r != address(0), "Unpatched");
        (bool ok, ) = r.delegatecall(msg.data);
        require(ok);
    }
}

// 4️⃣ Emergency Patch Override
contract EmergencyWindowPatch {
    string public emergencyFix;
    uint256 public expires;

    constructor() {
        expires = block.timestamp + 3600;
    }

    function emergencyPatch(string calldata value) external {
        require(block.timestamp <= expires, "Patch expired");
        emergencyFix = value;
    }
}

// 5️⃣ Immutable Data Rewire Patch
contract ImmutablePatch {
    bytes32 public constant HARDWIRED_SLOT = keccak256("patch.slot.immutable");

    function patch(bytes32 newValue) external {
        assembly {
            sstore(HARDWIRED_SLOT, newValue)
        }
    }

    function read() external view returns (bytes32 val) {
        assembly {
            val := sload(HARDWIRED_SLOT)
        }
    }
}

/* ================== PATCH ATTACKS ================== */

// 1️⃣ Pre-Patch Exploit Window
contract ExploitBeforePatch {
    function attack(address target) external {
        target.call(abi.encodeWithSignature("vulnerableLogic()"));
    }
}

// 2️⃣ Malicious Patch Logic
contract EvilLogic {
    function execute() external {
        selfdestruct(payable(msg.sender));
    }
}

// 3️⃣ Signature Drift Patch Abuse
contract DriftSigReplay {
    bytes32 public last;

    function replay(bytes32 hash) external {
        require(hash != last, "Drift blocked");
        last = hash;
    }
}

// 4️⃣ Time Race Patch Hijack
contract PatchRacer {
    function submitFastPatch(address patcher, string calldata payload) external {
        patcher.call(abi.encodeWithSignature("patch(string)", payload));
    }
}

// 5️⃣ Patch Drift Override
contract DriftedStorageWriter {
    function overwrite(address t, bytes32 k, bytes32 v) external {
        t.call(abi.encodeWithSignature("patch(bytes32,bytes32)", k, v));
    }
}

/* ================== PATCH DEFENSES ================== */

// 🛡️ 1 Patch Timelock Lockdown
contract TimelockedPatch {
    mapping(bytes32 => uint256) public queued;

    function queue(bytes32 id) external {
        queued[id] = block.timestamp + 2 hours;
    }

    function execute(bytes32 id) external view returns (bool) {
        return block.timestamp >= queued[id];
    }
}

// 🛡️ 2 Role-Multisig Patch Checker
contract PatchMultiSig {
    mapping(address => bool) public signers;
    uint8 public approvalCount;
    uint8 constant REQUIRED = 2;

    function approvePatch() external {
        require(!signers[msg.sender], "Already signed");
        signers[msg.sender] = true;
        approvalCount++;
    }

    function isApproved() public view returns (bool) {
        return approvalCount >= REQUIRED;
    }
}

// 🛡️ 3 Hash-Based Patch Commit
contract PatchHashCommit {
    mapping(bytes32 => bool) public committed;

    function commit(bytes32 hash) external {
        committed[hash] = true;
    }

    function validate(bytes calldata payload) external view returns (bool) {
        return committed[keccak256(payload)];
    }
}

// 🛡️ 4 Storage Integrity Diff
contract StorageDiffGuard {
    mapping(bytes32 => bytes32) public before;
    mapping(bytes32 => bytes32) public afterVal;

    function snapshotBefore(bytes32 key, bytes32 val) external {
        before[key] = val;
    }

    function snapshotAfter(bytes32 key, bytes32 val) external {
        afterVal[key] = val;
    }

    function check(bytes32 key) external view returns (bool) {
        return before[key] == afterVal[key];
    }
}

// 🛡️ 5 Selector Replay Guard
contract SelectorReplayGuard {
    mapping(bytes4 => bool) public used;

    function lock(bytes4 sel) external {
        require(!used[sel], "Selector already patched");
        used[sel] = true;
    }
}
