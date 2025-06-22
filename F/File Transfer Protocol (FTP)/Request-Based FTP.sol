// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * RequestFTP: Simulates FTP "pull-based" file access.
 * User must request file → owner approves → access expires.
 */
contract RequestFTP {
    struct File {
        string name;
        string hash;
        address owner;
    }

    struct DownloadAccess {
        uint256 expiresAt;
    }

    File[] public files;
    mapping(address => mapping(uint256 => DownloadAccess)) public fileAccess;

    event FileUploaded(uint256 indexed id, string name, address indexed uploader);
    event AccessGranted(address indexed to, uint256 fileId, uint256 expiresAt);

    function upload(string calldata name, string calldata hash) external {
        files.push(File(name, hash, msg.sender));
        emit FileUploaded(files.length - 1, name, msg.sender);
    }

    function requestDownload(uint256 fileId) external {
        require(fileId < files.length, "Invalid ID");
        // Logically simulate the request; owner must respond off-chain.
    }

    function grantAccess(uint256 fileId, address requester, uint256 duration) external {
        require(fileId < files.length, "Invalid ID");
        File storage f = files[fileId];
        require(msg.sender == f.owner, "Only owner");
        fileAccess[requester][fileId] = DownloadAccess(block.timestamp + duration);
        emit AccessGranted(requester, fileId, block.timestamp + duration);
    }

    function download(uint256 fileId) external view returns (string memory name, string memory hash) {
        require(fileId < files.length, "Invalid ID");
        require(fileAccess[msg.sender][fileId].expiresAt >= block.timestamp, "Access expired");
        File storage f = files[fileId];
        return (f.name, f.hash);
    }
}
