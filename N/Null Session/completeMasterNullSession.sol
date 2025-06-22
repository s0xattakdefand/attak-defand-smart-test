// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

interface IAutoSimExecutor {
    function autoReplay(address target, bytes calldata data) external;
}

interface IThreatUplink {
    function logThreat(bytes4 selector, string calldata tag, string calldata message) external;
}

contract NullSessionBot {
    using ECDSA for bytes32;

    address public owner;
    uint256 public failThreshold = 3;
    uint256 public scanBudget = 10;

    IAutoSimExecutor public autoSim;
    IThreatUplink public uplink;

    mapping(address => uint256) public failCount;
    mapping(address => bool) public blacklisted;
    mapping(bytes32 => bool) public seenReplay;
    mapping(bytes4 => uint256) public selectorEntropy;

    event DriftDetected(address indexed target, bytes4 selector, uint256 driftScore);
    event Blocked(address indexed target);
    event SignatureDrift(address indexed sender, bytes32 hash);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not authorized");
        _;
    }

    constructor(address _autoSim, address _uplink) {
        owner = msg.sender;
        autoSim = IAutoSimExecutor(_autoSim);
        uplink = IThreatUplink(_uplink);
    }

    // 🔁 Adaptive scanning of targets
    function scanTarget(address target) external onlyOwner {
        for (uint256 i = 0; i < scanBudget; i++) {
            bytes4 sel = bytes4(keccak256(abi.encodePacked(target, block.timestamp, i)));
            selectorEntropy[sel]++;
            bytes memory payload = abi.encodePacked(sel);

            (bool ok, ) = target.call(payload);
            emit DriftDetected(target, sel, selectorEntropy[sel]);

            if (!ok) {
                failCount[target]++;
                if (failCount[target] >= failThreshold && !blacklisted[target]) {
                    blacklisted[target] = true;
                    emit Blocked(target);
                    uplink.logThreat(sel, "NullSession", "Blocked target due to drift threshold");
                }
            } else {
                autoSim.autoReplay(target, payload);
            }
        }
    }

    // 🔁 Defense: prevent replay of same hash
    function logAndProtectReplay(bytes32 hash) external {
        require(!seenReplay[hash], "Replay detected");
        seenReplay[hash] = true;
    }

    // 🔐 MetaTx signature drift scanner (FIXED)
    function verifyMetaTxSig(bytes32 hash, bytes calldata sig, address expected) external {
        address signer = hash.toEthSignedMessageHash().recover(sig);
        if (signer != expected) {
            emit SignatureDrift(msg.sender, hash);
            uplink.logThreat(bytes4(hash), "MetaTxDrift", "Signature mismatch drift detected");
        }
    }

    // 🛡️ Optional fallback defense
    fallback() external payable {
        require(!blacklisted[msg.sender], "Access denied (null session blocked)");
    }

    // ⚙️ Admin controls
    function setThreshold(uint256 t) external onlyOwner {
        failThreshold = t;
    }

    function setBudget(uint256 b) external onlyOwner {
        scanBudget = b;
    }
}
