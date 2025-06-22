// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ConceptMapping — Secure Dynamic Role & Logic Selector Mapping Registry

contract ConceptMapping {
    address public owner;

    /// Role => Address (e.g., role => module, handler, vault)
    mapping(bytes32 => address) public roleToAddress;

    /// Function Selector => Logic Module (Composable execution mapping)
    mapping(bytes4 => address) public selectorToLogic;

    /// Freeze individual role entries to prevent tampering
    mapping(bytes32 => bool) public frozenRoles;
    mapping(bytes4 => bool) public frozenSelectors;

    event RoleMapped(bytes32 indexed role, address indexed target);
    event SelectorMapped(bytes4 indexed selector, address indexed logic);
    event RoleFrozen(bytes32 indexed role);
    event SelectorFrozen(bytes4 indexed selector);

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    /// --- Role Mapping (e.g., keccak256("VAULT_ADMIN")) => vault address --- ///
    function mapRole(bytes32 role, address target) external onlyOwner {
        require(!frozenRoles[role], "Role mapping frozen");
        roleToAddress[role] = target;
        emit RoleMapped(role, target);
    }

    function freezeRole(bytes32 role) external onlyOwner {
        frozenRoles[role] = true;
        emit RoleFrozen(role);
    }

    function getRoleMapping(bytes32 role) external view returns (address) {
        return roleToAddress[role];
    }

    /// --- Selector Mapping (e.g., bytes4(keccak256("mint(address,uint256)"))) => logic handler --- ///
    function mapSelector(bytes4 selector, address logic) external onlyOwner {
        require(!frozenSelectors[selector], "Selector mapping frozen");
        selectorToLogic[selector] = logic;
        emit SelectorMapped(selector, logic);
    }

    function freezeSelector(bytes4 selector) external onlyOwner {
        frozenSelectors[selector] = true;
        emit SelectorFrozen(selector);
    }

    function getSelectorMapping(bytes4 selector) external view returns (address) {
        return selectorToLogic[selector];
    }
}
