// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/Pausable.sol";

/**
 * @title NISTIR8011Dashboard
 * @notice On-chain “Agency Dashboard” and “Federal Dashboard” for tracking
 * software supply-chain security assessments per NISTIR 8011 Vol.1 guidelines.
 *
 * Roles:
 *   • DEFAULT_ADMIN_ROLE (“Federal”): can add/remove Agencies and pause/unpause.
 *   • AGENCY_ROLE: allowed to submit and update their own control assessments.
 *
 * Agencies submit assessments of individual controls:
 *   • controlId   – e.g. “SC-1”, “CM-2”
 *   • status      – 0 = Not Implemented, 1 = Partially, 2 = Fully
 *   • comments    – free-form notes or references
 *   • timestamp   – block timestamp of last update
 *
 * Federal Dashboard APIs:
 *   • viewAssessment(agency, controlId)
 *   • listAgencies()
 *   • listControls(agency)
 */
contract NISTIR8011Dashboard is AccessControl, Pausable {
    bytes32 public constant AGENCY_ROLE = keccak256("AGENCY_ROLE");

    struct Assessment {
        uint8  status;
        string comments;
        uint256 timestamp;
        bool exists;
    }

    // agency address => controlId => Assessment
    mapping(address => mapping(string => Assessment)) private _assessments;
    // agency address => list of controlIds
    mapping(address => string[]) private _controls;
    // agencies registry
    address[] private _agencies;
    mapping(address => bool) private _isAgency;

    event AgencyAdded(address indexed agency);
    event AgencyRemoved(address indexed agency);
    event AssessmentSubmitted(
        address indexed agency,
        string indexed controlId,
        uint8 status,
        string comments,
        uint256 timestamp
    );

    modifier onlyFederal() {
        require(
            hasRole(DEFAULT_ADMIN_ROLE, msg.sender),
            "Dashboard: not federal admin"
        );
        _;
    }

    modifier onlyAgency() {
        require(hasRole(AGENCY_ROLE, msg.sender), "Dashboard: not agency");
        _;
    }

    constructor(address federalAdmin) {
        _grantRole(DEFAULT_ADMIN_ROLE, federalAdmin);
    }

    /// @notice Add a new Agency (grant role & include in registry)
    function addAgency(address agency) external onlyFederal {
        require(!_isAgency[agency], "Dashboard: already agency");
        _grantRole(AGENCY_ROLE, agency);
        _isAgency[agency] = true;
        _agencies.push(agency);
        emit AgencyAdded(agency);
    }

    /// @notice Remove an Agency (revoke role & remove from registry)
    function removeAgency(address agency) external onlyFederal {
        require(_isAgency[agency], "Dashboard: not an agency");
        _revokeRole(AGENCY_ROLE, agency);
        _isAgency[agency] = false;
        // remove from _agencies array
        for (uint i = 0; i < _agencies.length; i++) {
            if (_agencies[i] == agency) {
                _agencies[i] = _agencies[_agencies.length - 1];
                _agencies.pop();
                break;
            }
        }
        emit AgencyRemoved(agency);
    }

    /// @notice Agency submits or updates a control assessment
    function submitAssessment(
        string calldata controlId,
        uint8 status,
        string calldata comments
    ) external whenNotPaused onlyAgency {
        require(status <= 2, "Dashboard: invalid status");

        Assessment storage a = _assessments[msg.sender][controlId];
        if (!a.exists) {
            _controls[msg.sender].push(controlId);
            a.exists = true;
        }
        a.status = status;
        a.comments = comments;
        a.timestamp = block.timestamp;

        emit AssessmentSubmitted(
            msg.sender,
            controlId,
            status,
            comments,
            a.timestamp
        );
    }

    /// @notice View a specific assessment for an agency
    function viewAssessment(address agency, string calldata controlId)
        external
        view
        returns (uint8 status, string memory comments, uint256 timestamp)
    {
        Assessment storage a = _assessments[agency][controlId];
        require(a.exists, "Dashboard: no assessment");
        return (a.status, a.comments, a.timestamp);
    }

    /// @notice List all registered agencies
    function listAgencies() external view returns (address[] memory) {
        return _agencies;
    }

    /// @notice List all control IDs assessed by an agency
    function listControls(address agency)
        external
        view
        returns (string[] memory)
    {
        return _controls[agency];
    }

    /// @notice Pause all agency submissions
    function pause() external onlyFederal {
        _pause();
    }

    /// @notice Unpause submissions
    function unpause() external onlyFederal {
        _unpause();
    }
}
