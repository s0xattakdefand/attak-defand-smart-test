// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title BuildingSecurityInMaturityModelAttackDefense - Attack and Defense Simulation for BSIMM in Solidity Smart Contracts
/// @author ChatGPT

/// @notice Insecure Security Maturity Framework (No Enforcement, No Verification)
contract InsecureBSIMM {
    enum Phase { Undefined, Initiated, Developed, Reviewed, Production }

    mapping(address => Phase) public projectPhase;

    event PhaseSet(address indexed project, Phase phase);

    function setPhase(address project, Phase phase) external {
        // 🔥 No checks, anyone can set any phase
        projectPhase[project] = phase;
        emit PhaseSet(project, phase);
    }
}

/// @notice Secure Security Maturity Framework with Immutable Audit Validation and Phase Enforcement
import "@openzeppelin/contracts/access/Ownable.sol";

contract SecureBSIMM is Ownable {
    enum Phase { Undefined, Initiated, Developed, Reviewed, Production }

    struct ProjectSecurityStatus {
        Phase currentPhase;
        bool auditCompleted;
        bool fuzzTestingCompleted;
        bool formalVerificationCompleted;
    }

    mapping(address => ProjectSecurityStatus) public projectStatus;

    event PhaseAdvanced(address indexed project, Phase newPhase);
    event SecurityCheckCompleted(address indexed project, string checkType);

    function initializeProject(address project) external onlyOwner {
        require(projectStatus[project].currentPhase == Phase.Undefined, "Already initialized");
        projectStatus[project].currentPhase = Phase.Initiated;
        emit PhaseAdvanced(project, Phase.Initiated);
    }

    function recordAuditCompletion(address project) external onlyOwner {
        projectStatus[project].auditCompleted = true;
        emit SecurityCheckCompleted(project, "Audit");
    }

    function recordFuzzCompletion(address project) external onlyOwner {
        projectStatus[project].fuzzTestingCompleted = true;
        emit SecurityCheckCompleted(project, "Fuzz Testing");
    }

    function recordFormalVerification(address project) external onlyOwner {
        projectStatus[project].formalVerificationCompleted = true;
        emit SecurityCheckCompleted(project, "Formal Verification");
    }

    function advancePhase(address project, Phase targetPhase) external onlyOwner {
        ProjectSecurityStatus storage status = projectStatus[project];

        require(uint8(targetPhase) == uint8(status.currentPhase) + 1, "Must advance sequentially");

        if (targetPhase == Phase.Reviewed) {
            require(status.auditCompleted, "Audit required for Reviewed phase");
        }
        if (targetPhase == Phase.Production) {
            require(status.fuzzTestingCompleted, "Fuzz testing required");
            require(status.formalVerificationCompleted, "Formal verification required");
        }

        status.currentPhase = targetPhase;
        emit PhaseAdvanced(project, targetPhase);
    }

    function getProjectPhase(address project) external view returns (Phase) {
        return projectStatus[project].currentPhase;
    }
}

/// @notice Intruder trying to fake security phase elevation
contract BSIMMIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function fakeAdvancePhase(address project, uint8 phaseIndex) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("setPhase(address,uint8)", project, phaseIndex)
        );
    }
}
