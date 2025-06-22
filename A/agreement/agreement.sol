// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// AgreementContract — Smart contract-based agreement tracker
contract AgreementContract {
    address public admin;

    enum Status { PENDING, ACCEPTED, REJECTED }

    struct Agreement {
        address partyA;
        address partyB;
        string ipfsURI;       // Link to PDF/JSON terms
        bytes32 termsHash;    // Hash of full agreement content
        Status status;
        uint256 createdAt;
    }

    Agreement[] public agreements;

    event AgreementCreated(uint256 indexed id, address partyA, address partyB);
    event AgreementResponded(uint256 indexed id, address responder, Status status);

    constructor() {
        admin = msg.sender;
    }

    function createAgreement(address partyB, string calldata ipfsURI, bytes32 termsHash) external returns (uint256) {
        agreements.push(Agreement(msg.sender, partyB, ipfsURI, termsHash, Status.PENDING, block.timestamp));
        uint256 id = agreements.length - 1;
        emit AgreementCreated(id, msg.sender, partyB);
        return id;
    }

    function respondToAgreement(uint256 id, bool accept) external {
        Agreement storage a = agreements[id];
        require(msg.sender == a.partyB, "Only counterparty can respond");
        require(a.status == Status.PENDING, "Already finalized");

        a.status = accept ? Status.ACCEPTED : Status.REJECTED;
        emit AgreementResponded(id, msg.sender, a.status);
    }

    function getAgreement(uint256 id) external view returns (Agreement memory) {
        return agreements[id];
    }

    function totalAgreements() external view returns (uint256) {
        return agreements.length;
    }
}
