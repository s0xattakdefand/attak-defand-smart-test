// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title DataLinkingAttackDefense - Full Attack and Defense Simulation for Data Linking Vulnerabilities
/// @author ChatGPT

/// @notice Secure contract managing data links safely
contract SecureDataLinking {
    address public owner;

    struct LinkedRecord {
        string dataDescription;
        address linkedContract;
        string linkedMetadataHash; // (e.g., IPFS hash)
        bool isImmutable;
    }

    mapping(uint256 => LinkedRecord) public records;
    uint256 public recordCounter;

    event RecordCreated(uint256 indexed id, address linkedContract, string metadataHash);
    event RecordUpdated(uint256 indexed id, address linkedContract, string metadataHash);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not authorized");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function createRecord(
        string memory _desc,
        address _linkedContract,
        string memory _metadataHash,
        bool _immutable
    ) external onlyOwner returns (uint256) {
        require(_linkedContract != address(0), "Invalid contract link");
        require(bytes(_metadataHash).length > 0, "Invalid metadata link");

        recordCounter++;
        records[recordCounter] = LinkedRecord({
            dataDescription: _desc,
            linkedContract: _linkedContract,
            linkedMetadataHash: _metadataHash,
            isImmutable: _immutable
        });

        emit RecordCreated(recordCounter, _linkedContract, _metadataHash);
        return recordCounter;
    }

    function updateLinks(
        uint256 _id,
        address _newLinkedContract,
        string memory _newMetadataHash
    ) external onlyOwner {
        require(records[_id].isImmutable == false, "Link is immutable");
        require(_newLinkedContract != address(0), "Invalid new link");
        require(bytes(_newMetadataHash).length > 0, "Invalid new metadata");

        records[_id].linkedContract = _newLinkedContract;
        records[_id].linkedMetadataHash = _newMetadataHash;

        emit RecordUpdated(_id, _newLinkedContract, _newMetadataHash);
    }

    function getLinkInfo(uint256 _id) external view returns (address, string memory) {
        LinkedRecord memory rec = records[_id];
        return (rec.linkedContract, rec.linkedMetadataHash);
    }
}

/// @notice Attack contract trying to inject bad links into SecureDataLinking
contract DataLinkingIntruder {
    address public target;

    constructor(address _target) {
        target = _target;
    }

    function tryInjectLink(uint256 _recordId, address badContract, string memory badHash) external returns (bool success) {
        (success, ) = target.call(
            abi.encodeWithSignature("updateLinks(uint256,address,string)", _recordId, badContract, badHash)
        );
        // If access control is properly set, this call must fail
    }
}
