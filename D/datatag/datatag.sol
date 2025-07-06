// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*=============================================================================
   TAGGING DEMO
   — “A non-hierarchical keyword or term assigned to a piece of information
     which helps describe an item and allows it to be found or processed
     automatically.”  (CNSSI-4009-2015 / ISA SSA)
=============================================================================*/

/*----------------------------------------------------------------------------
   SECTION 1 — VulnerableTagStore
   ⚠️ Anyone can tag or untag any item with any keyword; no ownership checks,
   no audit, no restriction ⇒ metadata pollution & sabotage.
----------------------------------------------------------------------------*/
contract VulnerableTagStore {
    // itemId ⇒ list of tags
    mapping(uint256 => bytes32[]) public tags;
    // itemId ⇒ tag ⇒ exists?
    mapping(uint256 => mapping(bytes32 => bool)) public tagExists;

    event TagAdded(uint256 indexed itemId, bytes32 tag, address indexed by);
    event TagRemoved(uint256 indexed itemId, bytes32 tag, address indexed by);

    // Anyone can add any tag to any item
    function addTag(uint256 itemId, bytes32 tag) external {
        require(!tagExists[itemId][tag], "Tag already exists");
        tags[itemId].push(tag);
        tagExists[itemId][tag] = true;
        emit TagAdded(itemId, tag, msg.sender);
    }

    // Anyone can remove any tag from any item
    function removeTag(uint256 itemId, bytes32 tag) external {
        require(tagExists[itemId][tag], "Tag does not exist");
        // remove from array (swap‐and‐pop)
        bytes32[] storage arr = tags[itemId];
        for (uint i = 0; i < arr.length; i++) {
            if (arr[i] == tag) {
                arr[i] = arr[arr.length - 1];
                arr.pop();
                break;
            }
        }
        tagExists[itemId][tag] = false;
        emit TagRemoved(itemId, tag, msg.sender);
    }

    // Retrieve all tags for an item
    function getTags(uint256 itemId) external view returns (bytes32[] memory) {
        return tags[itemId];
    }
}

/*----------------------------------------------------------------------------
   SECTION 2 — Ownable & RBAC helpers
----------------------------------------------------------------------------*/
abstract contract Ownable {
    address private _owner;
    event OwnershipTransferred(address indexed oldOwner, address indexed newOwner);
    constructor() { _owner = msg.sender; emit OwnershipTransferred(address(0), _owner); }
    modifier onlyOwner() { require(msg.sender == _owner, "Ownable: not owner"); _; }
    function owner() public view returns (address) { return _owner; }
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Ownable: zero address");
        emit OwnershipTransferred(_owner, newOwner);
        _owner = newOwner;
    }
}

abstract contract RBAC is Ownable {
    bytes32 public constant TAGGER_ROLE = keccak256("TAGGER_ROLE");

    mapping(bytes32 => mapping(address => bool)) private _roles;
    event RoleGranted(bytes32 indexed role, address indexed account);
    event RoleRevoked(bytes32 indexed role, address indexed account);

    modifier onlyRole(bytes32 role) {
        require(_roles[role][msg.sender], "RBAC: access denied");
        _;
    }

    constructor() {
        _grantRole(TAGGER_ROLE, msg.sender);
    }

    function grantRole(bytes32 role, address account) external onlyOwner {
        _grantRole(role, account);
    }
    function revokeRole(bytes32 role, address account) external onlyOwner {
        _revokeRole(role, account);
    }
    function hasRole(bytes32 role, address account) public view returns (bool) {
        return _roles[role][account];
    }

    function _grantRole(bytes32 role, address account) internal {
        if (!_roles[role][account]) {
            _roles[role][account] = true;
            emit RoleGranted(role, account);
        }
    }
    function _revokeRole(bytes32 role, address account) internal {
        if (_roles[role][account]) {
            _roles[role][account] = false;
            emit RoleRevoked(role, account);
        }
    }
}

/*----------------------------------------------------------------------------
   SECTION 3 — SafeTagRegistry
   ✅ Only item owners or accounts with TAGGER_ROLE may tag/untag; items
   are registered with owners; audit events record actor identity.
----------------------------------------------------------------------------*/
contract SafeTagRegistry is RBAC {
    // itemId ⇒ owner
    mapping(uint256 => address) public itemOwner;
    // itemId ⇒ list of tags
    mapping(uint256 => bytes32[]) public tags;
    // itemId ⇒ tag ⇒ exists?
    mapping(uint256 => mapping(bytes32 => bool)) public tagExists;

    event ItemRegistered(uint256 indexed itemId, address indexed owner);
    event TagAdded(uint256 indexed itemId, bytes32 tag, address indexed by);
    event TagRemoved(uint256 indexed itemId, bytes32 tag, address indexed by);

    // Register a new item; only owner can call
    function registerItem(uint256 itemId) external {
        require(itemOwner[itemId] == address(0), "Item already registered");
        itemOwner[itemId] = msg.sender;
        emit ItemRegistered(itemId, msg.sender);
    }

    // Add a tag; caller must be item owner or TAGGER_ROLE
    function addTag(uint256 itemId, bytes32 tag) external {
        require(itemOwner[itemId] != address(0), "Unknown item");
        require(
            msg.sender == itemOwner[itemId] || hasRole(TAGGER_ROLE, msg.sender),
            "Not authorized to tag"
        );
        require(!tagExists[itemId][tag], "Tag already exists");
        tags[itemId].push(tag);
        tagExists[itemId][tag] = true;
        emit TagAdded(itemId, tag, msg.sender);
    }

    // Remove a tag; caller must be item owner or TAGGER_ROLE
    function removeTag(uint256 itemId, bytes32 tag) external {
        require(itemOwner[itemId] != address(0), "Unknown item");
        require(
            msg.sender == itemOwner[itemId] || hasRole(TAGGER_ROLE, msg.sender),
            "Not authorized to remove tag"
        );
        require(tagExists[itemId][tag], "Tag does not exist");
        // swap-and-pop removal
        bytes32[] storage arr = tags[itemId];
        for (uint i = 0; i < arr.length; i++) {
            if (arr[i] == tag) {
                arr[i] = arr[arr.length - 1];
                arr.pop();
                break;
            }
        }
        tagExists[itemId][tag] = false;
        emit TagRemoved(itemId, tag, msg.sender);
    }

    // Get tags for an item
    function getTags(uint256 itemId) external view returns (bytes32[] memory) {
        return tags[itemId];
    }
}
