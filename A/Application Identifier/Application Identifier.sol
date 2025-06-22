// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// AppIDRegistry — Application Identifier registry & verifier
contract AppIDRegistry {
    address public admin;

    struct App {
        string name;
        string uri;           // IPFS or HTTPS metadata
        address creator;
        bytes32 appHash;      // keccak256(name + uri)
        bool active;
        uint256 createdAt;
    }

    mapping(uint256 => App) public apps;
    mapping(bytes32 => uint256) public hashToID;

    uint256 public totalApps;

    event AppRegistered(uint256 indexed id, string name, address creator);
    event AppDeactivated(uint256 indexed id);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function registerApp(string calldata name, string calldata uri) external onlyAdmin returns (uint256) {
        bytes32 appHash = keccak256(abi.encodePacked(name, uri));
        require(hashToID[appHash] == 0, "App already registered");

        uint256 id = ++totalApps;
        apps[id] = App(name, uri, msg.sender, appHash, true, block.timestamp);
        hashToID[appHash] = id;

        emit AppRegistered(id, name, msg.sender);
        return id;
    }

    function deactivateApp(uint256 id) external onlyAdmin {
        apps[id].active = false;
        emit AppDeactivated(id);
    }

    function getApp(uint256 id) external view returns (App memory) {
        return apps[id];
    }

    function verifyAID(bytes32 appHash) external view returns (bool) {
        uint256 id = hashToID[appHash];
        return id != 0 && apps[id].active;
    }
}
