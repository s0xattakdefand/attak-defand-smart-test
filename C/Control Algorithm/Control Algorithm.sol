// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract ContinuousThreatDetector {
    address public admin;
    uint256 public gasThreshold = 400_000;
    mapping(bytes4 => uint256) public callFrequency;
    mapping(bytes4 => uint256) public selectorEntropy;

    event ThreatDetected(bytes4 selector, address caller, string reason, uint256 gasUsed);
    event Anomaly(bytes4 selector, uint256 frequency, uint256 entropy);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not authorized");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function reportCall(bytes4 selector, uint256 gasUsed) external {
        callFrequency[selector]++;
        selectorEntropy[selector] ^= uint256(selector); // XOR adds drift signal

        if (gasUsed > gasThreshold) {
            emit ThreatDetected(selector, msg.sender, "High gas usage", gasUsed);
        }

        if (callFrequency[selector] > 20 && selectorEntropy[selector] % 7 == 0) {
            emit Anomaly(selector, callFrequency[selector], selectorEntropy[selector]);
        }
    }

    function updateGasThreshold(uint256 newThreshold) external onlyAdmin {
        gasThreshold = newThreshold;
    }
}
