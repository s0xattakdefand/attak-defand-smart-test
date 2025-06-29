// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/Pausable.sol";

/**
 * @title DataAccuracy
 * @notice
 *   Implements the NIST SP 800-188 “closeness of agreement” (accuracy) metric:
 *   the agreement between a reported property value and its true value.
 *
 * Roles:
 *   • DEFAULT_ADMIN_ROLE: can add/remove data providers, set true values, pause/unpause.
 *   • PROVIDER_ROLE: may submit measured values for properties.
 *
 * For each property:
 *   1. Admin registers a property ID and its oracle “true” value.
 *   2. Providers submit their measured values.
 *   3. Anyone can query the absolute error and relative error (as parts per million).
 */
contract DataAccuracy is AccessControl, Pausable {
    bytes32 public constant PROVIDER_ROLE = keccak256("PROVIDER_ROLE");

    struct Measurement {
        uint256 measuredValue;
        uint256 timestamp;
        bool    exists;
    }

    // propertyId => true (oracle) value
    mapping(bytes32 => uint256) public trueValue;
    // propertyId => provider => latest measurement
    mapping(bytes32 => mapping(address => Measurement)) private _measurements;
    // list of providers per property
    mapping(bytes32 => address[]) private _providers;

    event PropertyRegistered(bytes32 indexed propertyId, uint256 trueValue);
    event PropertyTrueValueUpdated(bytes32 indexed propertyId, uint256 newTrueValue);
    event MeasurementSubmitted(bytes32 indexed propertyId, address indexed provider, uint256 measuredValue);

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
    }

    modifier onlyAdmin() {
        require(hasRole(DEFAULT_ADMIN_ROLE, msg.sender), "DataAccuracy: not admin");
        _;
    }

    modifier onlyProvider() {
        require(hasRole(PROVIDER_ROLE, msg.sender), "DataAccuracy: not provider");
        _;
    }

    /// @notice Admin registers a new property with its oracle true value.
    function registerProperty(bytes32 propertyId, uint256 oracleValue) external onlyAdmin {
        require(oracleValue > 0, "DataAccuracy: true value zero");
        require(trueValue[propertyId] == 0, "DataAccuracy: already registered");
        trueValue[propertyId] = oracleValue;
        emit PropertyRegistered(propertyId, oracleValue);
    }

    /// @notice Admin may update the oracle true value if needed.
    function updateTrueValue(bytes32 propertyId, uint256 newValue) external onlyAdmin {
        require(trueValue[propertyId] != 0, "DataAccuracy: not registered");
        require(newValue > 0, "DataAccuracy: true value zero");
        trueValue[propertyId] = newValue;
        emit PropertyTrueValueUpdated(propertyId, newValue);
    }

    /// @notice Grant the PROVIDER_ROLE to an address.
    function addProvider(address provider) external onlyAdmin {
        grantRole(PROVIDER_ROLE, provider);
    }

    /// @notice Revoke PROVIDER_ROLE from an address.
    function removeProvider(address provider) external onlyAdmin {
        revokeRole(PROVIDER_ROLE, provider);
    }

    /// @notice Provider submits a measured value for a property.
    function submitMeasurement(bytes32 propertyId, uint256 measuredValue)
        external
        whenNotPaused
        onlyProvider
    {
        require(trueValue[propertyId] != 0, "DataAccuracy: property not registered");
        Measurement storage m = _measurements[propertyId][msg.sender];
        if (!m.exists) {
            _providers[propertyId].push(msg.sender);
            m.exists = true;
        }
        m.measuredValue = measuredValue;
        m.timestamp = block.timestamp;
        emit MeasurementSubmitted(propertyId, msg.sender, measuredValue);
    }

    /// @notice Get a provider’s latest measurement for a property.
    function getMeasurement(bytes32 propertyId, address provider)
        external
        view
        returns (uint256 measuredValue, uint256 timestamp)
    {
        Measurement storage m = _measurements[propertyId][provider];
        require(m.exists, "DataAccuracy: no measurement");
        return (m.measuredValue, m.timestamp);
    }

    /// @notice Compute absolute error: |measured – true|.
    function absoluteError(bytes32 propertyId, address provider) public view returns (uint256) {
        Measurement storage m = _measurements[propertyId][provider];
        require(m.exists, "DataAccuracy: no measurement");
        uint256 tv = trueValue[propertyId];
        return m.measuredValue > tv ? m.measuredValue - tv : tv - m.measuredValue;
    }

    /// @notice Compute relative error in parts-per-million (ppm):
    ///         absError / trueValue * 1e6.
    function relativeErrorPPM(bytes32 propertyId, address provider) external view returns (uint256) {
        uint256 absErr = absoluteError(propertyId, provider);
        // multiply first to retain precision
        return (absErr * 1_000_000) / trueValue[propertyId];
    }

    /// @notice List all providers who have submitted for a property.
    function listProviders(bytes32 propertyId) external view returns (address[] memory) {
        return _providers[propertyId];
    }

    /// @notice Pause provider submissions.
    function pause() external onlyAdmin {
        _pause();
    }

    /// @notice Unpause submissions.
    function unpause() external onlyAdmin {
        _unpause();
    }
}
