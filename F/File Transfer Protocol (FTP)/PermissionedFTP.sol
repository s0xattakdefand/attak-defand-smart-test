// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * PermissionedFTP: Only addresses with UPLOADER_ROLE can upload,
 * and only the owner or VIEWER_ROLE can download.
 */
contract PermissionedFTP is AccessControl {
    bytes32 public constant UPLOADER_ROLE = keccak256("UPLOADER_ROLE");
    bytes32 public constant VIEWER_ROLE = keccak256("VIEWER_ROLE");

    struct File {
        string name;
        string hash;
        address owner;
    }

    File[] public files;

    event FileUploaded(uint256 indexed id, string name, address indexed uploader);

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(UPLOADER_ROLE, admin);
        _grantRole(VIEWER_ROLE, admin);
    }

    function upload(string calldata name, string calldata hash) external onlyRole(UPLOADER_ROLE) {
        files.push(File(name, hash, msg.sender));
        emit FileUploaded(files.length - 1, name, msg.sender);
    }

    function download(uint256 fileId) external view returns (string memory name, string memory hash) {
        require(fileId < files.length, "Invalid ID");
        File storage f = files[fileId];
        require(msg.sender == f.owner || hasRole(VIEWER_ROLE, msg.sender), "Not authorized");
        return (f.name, f.hash);
    }

    function totalFiles() external view returns (uint256) {
        return files.length;
    }
}
