// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract GnutellaFileRequest {
    struct File {
        string ipfsCID;
        string fileName;
        uint256 sizeKB;
    }

    mapping(bytes32 => File) public files;

    function registerFile(string calldata cid, string calldata name, uint256 size) external {
        bytes32 id = keccak256(abi.encodePacked(msg.sender, cid));
        files[id] = File(cid, name, size);
    }

    function requestFile(address owner, string calldata cid) external view returns (File memory) {
        return files[keccak256(abi.encodePacked(owner, cid))];
    }
}
