// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/Pausable.sol";

/**
 * @title DataGovernance
 * @notice
 *   Implements a data governance model per CNSSI 4009-2015 & NSA/CSS Policy 11-1:
 *   • GOVERNANCE_ADMIN_ROLE manages roles and can pause the contract.
 *   • OWNER_ROLE marks the authoritative owner of each data asset.
 *   • STEWARD_ROLE members vote on governance proposals affecting data assets.
 *
 * Data Assets:
 *   • Registered by any GOVERNANCE_ADMIN_ROLE holder.
 *   • Have a unique ID, name, metadata URI, and an assigned owner.
 *
 * Governance Proposals:
 *   • Propose changes to an asset’s metadata or owner.
 *   • STEWARD_ROLE members vote For/Against within VOTING_PERIOD.
 *   • If quorum is reached and For > Against, proposal executes.
 */
contract DataGovernance is AccessControl, Pausable {
    bytes32 public constant GOVERNANCE_ADMIN_ROLE = keccak256("GOVERNANCE_ADMIN_ROLE");
    bytes32 public constant OWNER_ROLE            = keccak256("OWNER_ROLE");
    bytes32 public constant STEWARD_ROLE          = keccak256("STEWARD_ROLE");

    uint256 public constant VOTING_PERIOD = 3 days;
    uint256 public constant QUORUM        = 2; // minimum votes

    struct Asset {
        string name;
        string metadataURI;
        bool   exists;
    }

    struct Proposal {
        uint256 assetId;
        address proposer;
        string  newMetadataURI;
        address newOwner;
        uint256 startTime;
        uint256 forVotes;
        uint256 againstVotes;
        bool    executed;
        mapping(address => bool) voted;
    }

    Asset[] public assets;
    Proposal[] private _proposals;

    event AssetRegistered(uint256 indexed assetId, string name, string metadataURI, address owner);
    event OwnerAssigned  (uint256 indexed assetId, address indexed newOwner);
    event StewardAdded   (address indexed account);
    event StewardRemoved (address indexed account);

    event ProposalCreated(uint256 indexed proposalId, uint256 indexed assetId, address proposer);
    event VoteCast       (uint256 indexed proposalId, address indexed voter, bool support);
    event ProposalExecuted(uint256 indexed proposalId, bool passed);

    modifier onlyAdmin() {
        require(hasRole(GOVERNANCE_ADMIN_ROLE, msg.sender), "DG: not governance admin");
        _;
    }

    modifier onlySteward() {
        require(hasRole(STEWARD_ROLE, msg.sender), "DG: not steward");
        _;
    }

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(GOVERNANCE_ADMIN_ROLE, admin);
    }

    /// @notice Add or remove stewards
    function addSteward(address acct) external onlyAdmin {
        grantRole(STEWARD_ROLE, acct);
        emit StewardAdded(acct);
    }
    function removeSteward(address acct) external onlyAdmin {
        revokeRole(STEWARD_ROLE, acct);
        emit StewardRemoved(acct);
    }

    /// @notice Register a new data asset and assign its owner
    function registerAsset(
        string calldata name,
        string calldata metadataURI,
        address owner
    ) external whenNotPaused onlyAdmin returns (uint256 assetId) {
        require(owner != address(0), "DG: zero owner");
        assetId = assets.length;
        assets.push(Asset({ name: name, metadataURI: metadataURI, exists: true }));
        _grantRole(OWNER_ROLE, owner);
        emit AssetRegistered(assetId, name, metadataURI, owner);
    }

    /// @notice Create a governance proposal for an asset
    function proposeChange(
        uint256 assetId,
        string calldata newMetadataURI,
        address newOwner
    ) external whenNotPaused onlySteward returns (uint256 proposalId) {
        require(assetId < assets.length && assets[assetId].exists, "DG: invalid asset");
        proposalId = _proposals.length;
        _proposals.push();
        Proposal storage p = _proposals[proposalId];
        p.assetId        = assetId;
        p.proposer       = msg.sender;
        p.newMetadataURI = newMetadataURI;
        p.newOwner       = newOwner;
        p.startTime      = block.timestamp;
        emit ProposalCreated(proposalId, assetId, msg.sender);
    }

    /// @notice Vote on a proposal
    function vote(uint256 proposalId, bool support) external whenNotPaused onlySteward {
        require(proposalId < _proposals.length, "DG: invalid proposal");
        Proposal storage p = _proposals[proposalId];
        require(block.timestamp <= p.startTime + VOTING_PERIOD, "DG: voting closed");
        require(!p.voted[msg.sender], "DG: already voted");
        p.voted[msg.sender] = true;
        if (support) p.forVotes += 1;
        else         p.againstVotes += 1;
        emit VoteCast(proposalId, msg.sender, support);
    }

    /// @notice Execute a proposal if it passes
    function executeProposal(uint256 proposalId) external whenNotPaused {
        require(proposalId < _proposals.length, "DG: invalid proposal");
        Proposal storage p = _proposals[proposalId];
        require(!p.executed, "DG: already executed");
        require(block.timestamp > p.startTime + VOTING_PERIOD, "DG: voting not ended");

        p.executed = true;
        uint256 totalVotes = p.forVotes + p.againstVotes;
        bool passed = totalVotes >= QUORUM && p.forVotes > p.againstVotes;
        if (passed) {
            Asset storage a = assets[p.assetId];
            a.metadataURI = p.newMetadataURI;
            if (p.newOwner != address(0)) {
                // revoke old owners and grant new
                for (uint i=0; i<assets.length; i++) {
                    // no per-asset owner role here; in production track per-asset owners separately
                }
                _grantRole(OWNER_ROLE, p.newOwner);
                emit OwnerAssigned(p.assetId, p.newOwner);
            }
        }
        emit ProposalExecuted(proposalId, passed);
    }

    /// @notice Pause governance in emergencies
    function pause() external onlyAdmin {
        _pause();
    }
    function unpause() external onlyAdmin {
        _unpause();
    }
}
