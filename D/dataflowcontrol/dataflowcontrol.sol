// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/Pausable.sol";

/**
 * @title InformationFlowControl
 * @notice
 *   Implements CNSSI 4009-2015 “See” information-flow control:
 *   data items are labeled with classifications, and users have clearances;
 *   a user may only read (“see”) data at or below their clearance.
 *
 * Roles:
 *   • DEFAULT_ADMIN_ROLE: can pause/unpause, assign clearances, register data items.
 *   • READER_ROLE: may read data items within their clearance.
 *
 * Classifications:
 *   • Unclassified, Confidential, Secret, TopSecret.
 *
 * Data Model:
 *   • Each DataItem has an ID, off-chain pointer (URI), classification, and exists flag.
 *
 * Access Control:
 *   • Admin grants users clearances and the READER_ROLE.
 *   • Readers may call `getDataItem` only if their clearance ≥ item’s classification.
 */
contract InformationFlowControl is AccessControl, Pausable {
    bytes32 public constant READER_ROLE = keccak256("READER_ROLE");

    enum Classification { Unclassified, Confidential, Secret, TopSecret }

    struct DataItem {
        string          uri;         // off-chain pointer (IPFS, HTTPS…)
        Classification  level;       // classification label
        bool            exists;
    }

    // itemId ⇒ DataItem
    mapping(uint256 => DataItem) private _items;
    uint256 private _nextItemId = 1;

    // user ⇒ clearance level
    mapping(address => Classification) public clearance;

    event DataItemRegistered(uint256 indexed itemId, Classification level, string uri);
    event ClearanceAssigned(address indexed user, Classification level);

    modifier onlyAdmin() {
        require(hasRole(DEFAULT_ADMIN_ROLE, msg.sender), "IFC: not admin");
        _;
    }

    modifier onlyReader() {
        require(hasRole(READER_ROLE, msg.sender), "IFC: not reader");
        _;
    }

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
    }

    /// @notice Admin assigns a clearance level to a user and grants READER_ROLE
    function assignClearance(address user, Classification level) external onlyAdmin {
        clearance[user] = level;
        grantRole(READER_ROLE, user);
        emit ClearanceAssigned(user, level);
    }

    /// @notice Register a new data item with a classification label
    function registerDataItem(string calldata uri, Classification level)
        external
        onlyAdmin
        whenNotPaused
        returns (uint256 itemId)
    {
        require(bytes(uri).length > 0, "IFC: uri required");
        itemId = _nextItemId++;
        _items[itemId] = DataItem({ uri: uri, level: level, exists: true });
        emit DataItemRegistered(itemId, level, uri);
    }

    /// @notice Retrieve a data item’s URI if your clearance dominates its classification
    function getDataItem(uint256 itemId)
        external
        view
        onlyReader
        returns (string memory uri, Classification level)
    {
        DataItem storage d = _items[itemId];
        require(d.exists, "IFC: item not found");
        require(
            uint8(clearance[msg.sender]) >= uint8(d.level),
            "IFC: clearance too low"
        );
        return (d.uri, d.level);
    }

    /// @notice Pause all registry actions
    function pause() external onlyAdmin {
        _pause();
    }

    /// @notice Unpause registry actions
    function unpause() external onlyAdmin {
        _unpause();
    }
}
