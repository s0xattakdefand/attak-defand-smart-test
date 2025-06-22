// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// AdvisoryRegistry — Decentralized Web3 advisory bulletin system
contract AdvisoryRegistry {
    address public maintainer;

    enum Severity { LOW, MEDIUM, HIGH, CRITICAL }

    struct Advisory {
        string title;
        string referenceURI;
        Severity severity;
        address reporter;
        uint256 timestamp;
    }

    Advisory[] public advisories;

    event AdvisoryPublished(uint256 indexed id, string title, Severity severity, address reporter);

    modifier onlyMaintainer() {
        require(msg.sender == maintainer, "Not authorized");
        _;
    }

    constructor() {
        maintainer = msg.sender;
    }

    function publishAdvisory(
        string calldata title,
        string calldata referenceURI,
        Severity severity
    ) external onlyMaintainer returns (uint256) {
        advisories.push(Advisory(title, referenceURI, severity, msg.sender, block.timestamp));
        uint256 id = advisories.length - 1;
        emit AdvisoryPublished(id, title, severity, msg.sender);
        return id;
    }

    function getAdvisory(uint256 id) external view returns (Advisory memory) {
        return advisories[id];
    }

    function totalAdvisories() external view returns (uint256) {
        return advisories.length;
    }
}
