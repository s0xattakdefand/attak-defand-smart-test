// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * NaiveFTP: A dangerous, open-access file reference store.
 * Anyone can upload/download files. This simulates FTP without any control.
 */
contract NaiveFTP {
    struct File {
        string name;
        string hash; // IPFS or Arweave pointer
        address owner;
    }

    File[] public files;

    event FileUploaded(uint256 indexed id, string name, address indexed uploader);

    function upload(string calldata name, string calldata hash) external {
        files.push(File(name, hash, msg.sender));
        emit FileUploaded(files.length - 1, name, msg.sender);
    }

    function download(uint256 fileId) external view returns (string memory name, string memory hash) {
        require(fileId < files.length, "Invalid ID");
        File storage f = files[fileId];
        return (f.name, f.hash);
    }

    function totalFiles() external view returns (uint256) {
        return files.length;
    }
}
