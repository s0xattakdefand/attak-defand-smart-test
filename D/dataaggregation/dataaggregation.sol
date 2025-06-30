// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/Pausable.sol";

/**
 * @title DataAggregationControl
 * @notice Implements controls to prevent unapproved aggregation of data items
 * in accordance with CNSSI 4009-2015 (“aggregation effect”): combining
 * individually unclassified or low-classification items could result in
 * higher-level classification or be of use to an adversary.
 *
 * • ADMIN_ROLE may register data items and assign user clearances.
 * • Data owners register items with an off-chain URI and a classification level.
 * • Users have clearance levels; they may only request aggregations if
 *   their clearance ≥ the highest classification in the set.
 * • Aggregation requests emit events recording the combined classification.
 */
contract DataAggregationControl is AccessControl, Pausable {
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    enum Classification { Unclassified, Confidential, Secret, TopSecret }

    struct DataItem {
        address owner;
        string  uri;             // off-chain pointer (IPFS, HTTPS)
        Classification classLevel;
        bool    exists;
    }

    // itemId ⇒ DataItem
    mapping(uint256 => DataItem) private _items;
    uint256 private _nextItemId = 1;

    // user ⇒ clearance level
    mapping(address => Classification) private _clearance;

    // Aggregation request record
    event ItemRegistered(uint256 indexed itemId, address indexed owner, Classification classLevel, string uri);
    event ClearanceAssigned(address indexed user, Classification clearance);
    event AggregationRequested(address indexed user, uint256[] itemIds, Classification combinedLevel);

    modifier onlyAdmin() {
        require(hasRole(ADMIN_ROLE, msg.sender), "DAC: not admin");
        _;
    }

    modifier onlyItemOwner(uint256 itemId) {
        require(_items[itemId].exists, "DAC: item not found");
        require(_items[itemId].owner == msg.sender, "DAC: not item owner");
        _;
    }

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ADMIN_ROLE, admin);
    }

    /// @notice Register a new data item with classification and URI
    function registerItem(string calldata uri, Classification classLevel)
        external
        whenNotPaused
        returns (uint256 itemId)
    {
        itemId = _nextItemId++;
        _items[itemId] = DataItem({
            owner:      msg.sender,
            uri:        uri,
            classLevel: classLevel,
            exists:     true
        });
        emit ItemRegistered(itemId, msg.sender, classLevel, uri);
    }

    /// @notice ADMIN assigns clearance level to a user
    function assignClearance(address user, Classification clearance)
        external
        onlyAdmin
    {
        _clearance[user] = clearance;
        emit ClearanceAssigned(user, clearance);
    }

    /// @notice View a user's clearance
    function getClearance(address user) external view returns (Classification) {
        return _clearance[user];
    }

    /// @notice View metadata of a data item
    function getItem(uint256 itemId)
        external
        view
        returns (address owner, string memory uri, Classification classLevel)
    {
        DataItem storage itm = _items[itemId];
        require(itm.exists, "DAC: item not found");
        return (itm.owner, itm.uri, itm.classLevel);
    }

    /// @notice Request aggregation of multiple items; reverts if the user's clearance is insufficient
    function requestAggregation(uint256[] calldata itemIds)
        external
        whenNotPaused
    {
        require(itemIds.length > 0, "DAC: no item IDs");

        Classification combined = Classification.Unclassified;
        for (uint256 i = 0; i < itemIds.length; i++) {
            DataItem storage itm = _items[itemIds[i]];
            require(itm.exists, "DAC: invalid item");
            // highest classification dominates
            if (uint8(itm.classLevel) > uint8(combined)) {
                combined = itm.classLevel;
            }
        }

        // enforce clearance
        require(uint8(_clearance[msg.sender]) >= uint8(combined),
            "DAC: clearance too low");

        emit AggregationRequested(msg.sender, itemIds, combined);
    }

    /// @notice Pause registry in emergencies
    function pause() external onlyAdmin {
        _pause();
    }

    /// @notice Unpause registry actions
    function unpause() external onlyAdmin {
        _unpause();
    }
}
