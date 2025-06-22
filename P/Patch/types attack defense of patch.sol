// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/* ======================= TYPES ======================= */

// 1️⃣ Proxy Upgrade Patch
contract PatchProxy {
    address public logic;

    function updateLogic(address newLogic) external {
        logic = newLogic;
    }

    fallback() external payable {
        address impl = logic;
        require(impl != address(0), "No logic");
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}

// 2️⃣ Role-Based Hotfix
contract Hotfixer {
    address public admin;
    string public patchedMessage;

    modifier onlyAdmin() {
        require(msg.sender == admin, "Denied");
        _;
    }

    function applyPatch(string calldata msgTxt) external onlyAdmin {
        patchedMessage = msgTxt;
    }
}

// 3️⃣ Selector Routing Patch
contract SelectorPatcher {
    mapping(bytes4 => address) public route;

    function patch(bytes4 selector, address target) external {
        route[selector] = target;
    }

    fallback() external {
        address target = route[msg.sig];
        require(target != address(0), "Missing");
        (bool ok, ) = target.delegatecall(msg.data);
        require(ok);
    }
}

// 4️⃣ Eternal Storage Patch
contract EternalPatch {
    mapping(bytes32 => bytes32) internal store;

    function patch(bytes32 key, bytes32 val) external {
        store[key] = val;
    }

    function get(bytes32 key) external view returns (bytes32) {
        return store[key];
    }
}

// 5️⃣ Emergency Time Patch
contract EmergencyPatch {
    uint256 public patchWindowEnd;
    string public patchedValue;

    constructor() {
        patchWindowEnd = block.timestamp + 1 hours;
    }

    function emergencyPatch(string calldata v) external {
        require(block.timestamp <= patchWindowEnd, "Window closed");
        patchedValue = v;
    }
}

/* ======================= ATTACKS ======================= */

// 1️⃣ Patch Delay Exploit
contract PatchDelayExploit {
    function attack(address vulnerable) external {
        vulnerable.call(abi.encodeWithSignature("exploit()"));
    }
}

// 2️⃣ Malicious Logic Swap
contract EvilPatchLogic {
    function pwn() external {
        selfdestruct(payable(msg.sender));
    }
}

// 3️⃣ Role Patch Takeover
contract PatchHijacker {
    function overwrite(address patcher) external {
        patcher.call(abi.encodeWithSignature("applyPatch(string)", "Hacked"));
    }
}

// 4️⃣ Reentry Drift Exploit
contract ReentryAfterPatch {
    function trigger(address proxy, bytes calldata data) external {
        proxy.call(data);
    }
}

// 5️⃣ Eternal Patch Backdoor
contract BackdoorPatch {
    function write(address ep, bytes32 k, bytes32 v) external {
        ep.call(abi.encodeWithSignature("patch(bytes32,bytes32)", k, v));
    }
}

/* ======================= DEFENSES ======================= */

// 🛡️ 1 Timelock Patcher
contract PatchTimelock {
    mapping(bytes32 => uint256) public queued;

    function queuePatch(bytes32 id) external {
        queued[id] = block.timestamp + 2 hours;
    }

    function executePatch(bytes32 id) external view returns (bool) {
        return block.timestamp >= queued[id];
    }
}

// 🛡️ 2 MultiSig Patch Approval (abstract)
contract MultiSigPatchGuard {
    mapping(address => bool) public approvers;
    uint8 public approvals;
    uint8 constant required = 2;

    function approve() external {
        require(!approvers[msg.sender], "Already approved");
        approvers[msg.sender] = true;
        approvals++;
    }

    function canPatch() external view returns (bool) {
        return approvals >= required;
    }
}

// 🛡️ 3 Selector Logger
contract PatchLogger {
    event Patched(bytes4 indexed sel, address newLogic);

    function log(bytes4 sel, address t) external {
        emit Patched(sel, t);
    }
}

// 🛡️ 4 Logic Hash Verifier
contract LogicHashLock {
    bytes32 public immutable baseline;

    constructor(bytes32 h) {
        baseline = h;
    }

    function check(address logic) external view returns (bool) {
        return keccak256(abi.encodePacked(logic.code)) == baseline;
    }
}

// 🛡️ 5 Patch Storage Diff Checker
contract PatchDiff {
    mapping(bytes32 => bytes32) public beforePatch;
    mapping(bytes32 => bytes32) public afterPatch;

    function snapshotBefore(bytes32 key, bytes32 val) external {
        beforePatch[key] = val;
    }

    function snapshotAfter(bytes32 key, bytes32 val) external {
        afterPatch[key] = val;
    }

    function diff(bytes32 key) external view returns (bool) {
        return beforePatch[key] != afterPatch[key];
    }
}
