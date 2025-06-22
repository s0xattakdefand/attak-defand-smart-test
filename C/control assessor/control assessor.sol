// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ControlAssessor — Audits another contract's access and status controls
interface ITargetContract {
    function owner() external view returns (address);
    function paused() external view returns (bool);
    function admins(address) external view returns (bool);
    function operators(address) external view returns (bool);
}

contract ControlAssessor {
    address public assessor;
    mapping(address => bool) public trustedTargets;

    event TargetAudited(address target, bool isPaused, bool assessorIsAdmin, bool assessorIsOperator);
    event TrustedTargetAdded(address target);
    event TrustedTargetRemoved(address target);

    modifier onlyAssessor() {
        require(msg.sender == assessor, "Not assessor");
        _;
    }

    constructor() {
        assessor = msg.sender;
    }

    function addTrustedTarget(address target) external onlyAssessor {
        trustedTargets[target] = true;
        emit TrustedTargetAdded(target);
    }

    function removeTrustedTarget(address target) external onlyAssessor {
        trustedTargets[target] = false;
        emit TrustedTargetRemoved(target);
    }

    /// ✅ Assess a contract's control surface (access + pause state)
    function assessControl(address target) external view returns (
        bool paused,
        bool isAdmin,
        bool isOperator
    ) {
        require(trustedTargets[target], "Untrusted contract");

        paused = ITargetContract(target).paused();
        isAdmin = ITargetContract(target).admins(assessor);
        isOperator = ITargetContract(target).operators(assessor);
    }

    /// Emits event after assessment (optional hook for automation)
    function auditTarget(address target) external {
        require(trustedTargets[target], "Not whitelisted");

        bool paused = ITargetContract(target).paused();
        bool isAdmin = ITargetContract(target).admins(assessor);
        bool isOperator = ITargetContract(target).operators(assessor);

        emit TargetAudited(target, paused, isAdmin, isOperator);
    }
}
