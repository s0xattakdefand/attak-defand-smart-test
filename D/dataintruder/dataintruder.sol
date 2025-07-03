// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/Pausable.sol";

/**
 * @title DataDisclosureProtection
 * @notice
 *   Implements controls to prevent a data user from disclosing information about
 *   small populations (identification or attribution), per NIST SP 800-188 & OECD.
 *
 *   • ADMIN_ROLE can register populations with their sizes and set a minimum k-anonymity threshold.
 *   • DATA_USER_ROLE may request aggregate data for a population only if its size ≥ threshold.
 *   • Attempts to query smaller populations are rejected to prevent re-identification.
 */
contract DataDisclosureProtection is AccessControl, Pausable {
    bytes32 public constant ADMIN_ROLE     = keccak256("ADMIN_ROLE");
    bytes32 public constant DATA_USER_ROLE = keccak256("DATA_USER_ROLE");

    struct Population {
        string description;  // e.g. "Age 30-40 in Region X"
        uint256 size;        // total number of individuals
        bool    exists;
    }

    // populationId ⇒ Population
    mapping(uint256 => Population) private _populations;
    uint256 private _nextPopulationId = 1;

    // minimum population size to allow disclosure
    uint256 public kThreshold;

    event ThresholdSet(uint256 newThreshold);
    event PopulationRegistered(uint256 indexed populationId, string description, uint256 size);
    event PopulationSizeUpdated(uint256 indexed populationId, uint256 newSize);
    event DisclosureRequested(uint256 indexed populationId, address indexed user, bool allowed);

    modifier onlyAdmin() {
        require(hasRole(ADMIN_ROLE, msg.sender), "DDP: not admin");
        _;
    }

    modifier onlyDataUser() {
        require(hasRole(DATA_USER_ROLE, msg.sender), "DDP: not a data user");
        _;
    }

    constructor(address admin, uint256 initialThreshold) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ADMIN_ROLE, admin);
        kThreshold = initialThreshold;
        emit ThresholdSet(initialThreshold);
    }

    /// @notice Grant DATA_USER_ROLE to an account
    function addDataUser(address acct) external onlyAdmin {
        grantRole(DATA_USER_ROLE, acct);
    }

    /// @notice Revoke DATA_USER_ROLE from an account
    function removeDataUser(address acct) external onlyAdmin {
        revokeRole(DATA_USER_ROLE, acct);
    }

    /// @notice Pause all operations
    function pause() external onlyAdmin {
        _pause();
    }

    /// @notice Unpause all operations
    function unpause() external onlyAdmin {
        _unpause();
    }

    /// @notice Set the k-anonymity threshold
    function setThreshold(uint256 newThreshold) external onlyAdmin {
        require(newThreshold > 0, "DDP: threshold must be > 0");
        kThreshold = newThreshold;
        emit ThresholdSet(newThreshold);
    }

    /// @notice Register a new population group
    function registerPopulation(string calldata description, uint256 size)
        external
        onlyAdmin
        whenNotPaused
        returns (uint256 populationId)
    {
        require(size > 0, "DDP: size must be > 0");
        populationId = _nextPopulationId++;
        _populations[populationId] = Population({
            description: description,
            size:        size,
            exists:      true
        });
        emit PopulationRegistered(populationId, description, size);
    }

    /// @notice Update the size of an existing population
    function updatePopulationSize(uint256 populationId, uint256 newSize)
        external
        onlyAdmin
        whenNotPaused
    {
        Population storage p = _populations[populationId];
        require(p.exists, "DDP: unknown population");
        require(newSize > 0, "DDP: size must be > 0");
        p.size = newSize;
        emit PopulationSizeUpdated(populationId, newSize);
    }

    /**
     * @notice Request disclosure of aggregate data for a population.
     * @dev Returns true if p.size ≥ kThreshold, false (and reverts) otherwise.
     */
    function requestDisclosure(uint256 populationId)
        external
        whenNotPaused
        onlyDataUser
        returns (bool)
    {
        Population storage p = _populations[populationId];
        require(p.exists, "DDP: unknown population");

        bool allowed = p.size >= kThreshold;
        emit DisclosureRequested(populationId, msg.sender, allowed);
        require(allowed, "DDP: population too small for disclosure");

        return true;
    }

    /// @notice Get population metadata
    function getPopulation(uint256 populationId)
        external
        view
        returns (string memory description, uint256 size)
    {
        Population storage p = _populations[populationId];
        require(p.exists, "DDP: unknown population");
        return (p.description, p.size);
    }
}
