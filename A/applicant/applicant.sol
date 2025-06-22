// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract ApplicantRegistry {
    enum Status { NONE, PENDING, APPROVED, REJECTED }

    struct Application {
        address applicant;
        string role;
        string metadataURI; // e.g., IPFS/Arweave data
        Status status;
        uint256 submittedAt;
    }

    mapping(bytes32 => Application) public applications;
    mapping(address => uint256) public applicantNonce;

    event ApplicationSubmitted(bytes32 appId, address indexed applicant, string role);
    event ApplicationReviewed(bytes32 appId, Status status);

    function submitApplication(string calldata role, string calldata metadataURI) external returns (bytes32) {
        uint256 nonce = ++applicantNonce[msg.sender];
        bytes32 appId = keccak256(abi.encodePacked(msg.sender, role, metadataURI, nonce));
        require(applications[appId].status == Status.NONE, "Already submitted");

        applications[appId] = Application({
            applicant: msg.sender,
            role: role,
            metadataURI: metadataURI,
            status: Status.PENDING,
            submittedAt: block.timestamp
        });

        emit ApplicationSubmitted(appId, msg.sender, role);
        return appId;
    }

    function reviewApplication(bytes32 appId, bool approve) external {
        Application storage app = applications[appId];
        require(app.status == Status.PENDING, "Not pending");

        app.status = approve ? Status.APPROVED : Status.REJECTED;
        emit ApplicationReviewed(appId, app.status);
    }

    function getApplication(bytes32 appId) external view returns (Application memory) {
        return applications[appId];
    }
}
