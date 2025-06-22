// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title FTPLedger
 * @notice A file transfer protocol registry with an audit trail.
 * Every upload and download is recorded on-chain.
 */
contract FTPLedger {
    struct File {
        string name;
        string hash; // e.g., IPFS or Arweave content hash
        address owner;
    }

    File[] public files;

    event FileUploaded(uint256 indexed id, string name, address indexed uploader);
    event FileDownloaded(uint256 indexed id, address indexed downloader, uint256 timestamp);

    /**
     * @notice Upload a new file reference.
     * @param name The name of the file.
     * @param hash The IPFS or Arweave content hash.
     */
    function upload(string calldata name, string calldata hash) external {
        files.push(File(name, hash, msg.sender));
        emit FileUploaded(files.length - 1, name, msg.sender);
    }

    /**
     * @notice Download file metadata (logged with timestamp).
     * @param fileId The ID of the file.
     * @return name The filename.
     * @return hash The content hash.
     */
    function download(uint256 fileId) external returns (string memory name, string memory hash) {
        require(fileId < files.length, "Invalid file ID");
        File storage f = files[fileId];
        emit FileDownloaded(fileId, msg.sender, block.timestamp);
        return (f.name, f.hash);
    }

    /**
     * @notice Returns how many files have been uploaded.
     */
    function totalFiles() external view returns (uint256) {
        return files.length;
    }
}
