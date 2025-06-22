// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/* ================== POLYINSTANTIATION TYPES ================== */

// 1️⃣ Role-Based Instance
contract RoleBasedData {
    mapping(address => uint8) public role;
    mapping(string => mapping(uint8 => string)) private viewData;

    function setRole(address user, uint8 r) external {
        role[user] = r;
    }

    function setView(string calldata key, uint8 r, string calldata val) external {
        viewData[key][r] = val;
    }

    function getView(string calldata key) external view returns (string memory) {
        return viewData[key][role[msg.sender]];
    }
}

// 2️⃣ ZK Scoped Instance (mocked)
contract ZKInstance {
    mapping(bytes32 => string) public zkData;

    function setZK(bytes32 zkID, string calldata data) external {
        zkData[zkID] = data;
    }

    function viewZK(bytes32 zkID) external view returns (string memory) {
        require(zkID != bytes32(0), "ZK not bound");
        return zkData[zkID];
    }
}

// 3️⃣ Metadata Fork
contract ForkedMetadata {
    mapping(uint256 => mapping(address => string)) public meta;

    function set(uint256 tokenId, string calldata val) external {
        meta[tokenId][msg.sender] = val;
    }

    function uri(uint256 tokenId) external view returns (string memory) {
        return meta[tokenId][msg.sender];
    }
}

// 4️⃣ Version Fork Snapshot
contract VersionState {
    mapping(bytes32 => string) public snapshots;

    function commit(string calldata d, uint256 blockNumber) external {
        bytes32 h = keccak256(abi.encodePacked(blockNumber));
        snapshots[h] = d;
    }

    function viewAt(uint256 blockNumber) external view returns (string memory) {
        return snapshots[keccak256(abi.encodePacked(blockNumber))];
    }
}

// 5️⃣ Token-Gated View
contract PermitView {
    mapping(address => bool) public access;
    string private secretData;

    function grant(address u, bool y) external {
        access[u] = y;
    }

    function viewSecret() external view returns (string memory) {
        require(access[msg.sender], "No access");
        return secretData;
    }

    function setSecret(string calldata d) external {
        secretData = d;
    }
}
