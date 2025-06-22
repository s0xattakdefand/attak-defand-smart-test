// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// common errors
error Seg__NotAuthorized();
error Seg__AlreadyUploaded();
error Seg__BadProof();

/////////////////////////////////////////////////////////////////////
// 1. NETWORK SEGMENTATION – Vulnerable vs Safe
/////////////////////////////////////////////////////////////////////
contract NetworkSegmentVuln {
    event Action(address who);
    // ❌ no address check
    function segmentedAction() external {
        emit Action(msg.sender);
    }
}
contract Attack_NetworkSegment {
    NetworkSegmentVuln public target;
    constructor(NetworkSegmentVuln _t) { target = _t; }
    function exploit() external {
        target.segmentedAction(); // succeeds even if caller shouldn't be segmented in
    }
}

contract NetworkSegmentSafe {
    mapping(address => bool) public whitelist;
    event Action(address who);
    constructor(address[] memory allowed) {
        for (uint i; i < allowed.length; i++) {
            whitelist[allowed[i]] = true;
        }
    }
    function segmentedAction() external {
        if (!whitelist[msg.sender]) revert Seg__NotAuthorized();
        emit Action(msg.sender);
    }
    function grant(address who) external {
        // in practice restrict to an admin – omitted for brevity
        whitelist[who] = true;
    }
}

/////////////////////////////////////////////////////////////////////
// 2. DATA SEGMENTATION – Vulnerable vs Safe (Merkle chunks)
/////////////////////////////////////////////////////////////////////
contract DataSegVuln {
    mapping(uint256 => bytes) public chunks;
    // ❌ no integrity check: any data allowed
    function uploadChunk(uint256 idx, bytes calldata data) external {
        chunks[idx] = data;
    }
}
contract Attack_DataSeg {
    DataSegVuln public target;
    constructor(DataSegVuln _t) { target = _t; }
    function exploit(uint256 idx, bytes calldata badData) external {
        target.uploadChunk(idx, badData); // Naïve contract accepts it
    }
}

contract DataSegSafe {
    bytes32 public immutable merkleRoot;
    mapping(uint256 => bool) public uploaded;
    event ChunkUploaded(uint256 indexed idx);

    constructor(bytes32 _root) { merkleRoot = _root; }

    /// @param idx    zero‑based chunk index
    /// @param data   raw chunk bytes
    /// @param proof  Merkle proof for leaf = keccak256(idx|data)
    function uploadChunk(
        uint256 idx,
        bytes   calldata data,
        bytes32[] calldata proof
    ) external {
        if (uploaded[idx]) revert Seg__AlreadyUploaded();
        // verify integrity
        bytes32 leaf = keccak256(abi.encodePacked(idx, data));
        if (!_verifyProof(leaf, proof)) revert Seg__BadProof();
        uploaded[idx] = true;
        emit ChunkUploaded(idx);
        // store or process data off‑chain…
    }

    function _verifyProof(bytes32 leaf, bytes32[] calldata proof) internal view returns (bool) {
        bytes32 h = leaf;
        for (uint i; i < proof.length; i++) {
            bytes32 p = proof[i];
            if (h < p) h = keccak256(abi.encodePacked(h, p));
            else      h = keccak256(abi.encodePacked(p, h));
        }
        return h == merkleRoot;
    }
}

/////////////////////////////////////////////////////////////////////
// 3. FUNCTION SEGMENTATION – Vulnerable vs Safe
/////////////////////////////////////////////////////////////////////
contract FunctionSegmentVuln {
    uint256 public secret;
    // ❌ no caller restriction
    function setSecret(uint256 v) external {
        secret = v;
    }
}
contract Attack_FunctionSegment {
    FunctionSegmentVuln public target;
    constructor(FunctionSegmentVuln _t) { target = _t; }
    function exploit(uint256 newSecret) external {
        target.setSecret(newSecret); // anyone can overwrite!
    }
}

contract FunctionSegmentSafe {
    mapping(bytes32 => mapping(address => bool)) public segmentRole;
    uint256 public secret;
    bytes32 public constant SEG_SECRET = keccak256("SEG_SECRET");

    constructor() {
        // grant deployer the “secret” segment
        segmentRole[SEG_SECRET][msg.sender] = true;
    }

    function setSecret(uint256 v) external {
        if (!segmentRole[SEG_SECRET][msg.sender]) revert Seg__NotAuthorized();
        secret = v;
    }

    function grant(bytes32 segment, address who) external {
        // in practice restrict to an admin – omitted for brevity
        segmentRole[segment][who] = true;
    }
}
