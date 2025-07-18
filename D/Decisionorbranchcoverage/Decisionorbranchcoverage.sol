// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
 * BRANCH COVERAGE TRACKER
 * NISTIR 7878 — “The percentage of branches that have been evaluated to both true
 * and false by a test set.”
 *
 * This contract allows registering control‐flow branch IDs, recording when each
 * branch is evaluated true or false, and computing the overall branch coverage.
 */

contract BranchCoverage {
    struct Branch {
        bool seenTrue;
        bool seenFalse;
        bool exists;
    }

    // branchId → Branch info
    mapping(uint256 => Branch) private _branches;
    uint256[] private _branchIds;

    // Contract owner (who may register new branches)
    address public owner;

    // Events
    event BranchRegistered(uint256 indexed branchId);
    event BranchEvaluated(uint256 indexed branchId, bool outcome);
    event CoverageUpdated(uint256 coveredBranches, uint256 totalBranches, uint256 percentage);

    modifier onlyOwner() {
        require(msg.sender == owner, "BranchCoverage: caller is not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    /// @notice Register a new branch ID to track
    function registerBranch(uint256 branchId) external onlyOwner {
        require(!_branches[branchId].exists, "BranchCoverage: branch already registered");
        _branches[branchId] = Branch({ seenTrue: false, seenFalse: false, exists: true });
        _branchIds.push(branchId);
        emit BranchRegistered(branchId);
    }

    /// @notice Record that a branch was evaluated with a given outcome
    function evaluateBranch(uint256 branchId, bool outcome) external {
        Branch storage b = _branches[branchId];
        require(b.exists, "BranchCoverage: unknown branch");
        if (outcome) {
            b.seenTrue = true;
        } else {
            b.seenFalse = true;
        }
        emit BranchEvaluated(branchId, outcome);
    }

    /// @notice Get the recorded outcomes for a branch
    function getBranch(uint256 branchId) external view returns (bool seenTrue, bool seenFalse) {
        Branch storage b = _branches[branchId];
        require(b.exists, "BranchCoverage: unknown branch");
        return (b.seenTrue, b.seenFalse);
    }

    /// @notice Compute and emit the current branch coverage percentage
    function updateCoverage() external {
        uint256 total = _branchIds.length;
        uint256 covered = 0;
        for (uint256 i = 0; i < total; i++) {
            Branch storage b = _branches[_branchIds[i]];
            if (b.seenTrue && b.seenFalse) {
                covered++;
            }
        }
        uint256 percentage = total == 0 ? 100 : (covered * 100) / total;
        emit CoverageUpdated(covered, total, percentage);
    }

    /// @notice View current branch coverage without emitting an event
    function coverage() external view returns (uint256 coveredBranches, uint256 totalBranches, uint256 percentage) {
        uint256 total = _branchIds.length;
        uint256 covered = 0;
        for (uint256 i = 0; i < total; i++) {
            Branch storage b = _branches[_branchIds[i]];
            if (b.seenTrue && b.seenFalse) {
                covered++;
            }
        }
        uint256 perc = total == 0 ? 100 : (covered * 100) / total;
        return (covered, total, perc);
    }
}
