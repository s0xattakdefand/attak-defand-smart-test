pragma solidity ^0.8.21;

import "@openzeppelin/contracts/access/AccessControl.sol";

contract LeastPrivilegeRBAC is AccessControl {
    bytes32 public constant MINTER_ROLE = keccak256("MINTER");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER");

    function mint(address to, uint256 amount) external onlyRole(MINTER_ROLE) {
        // safe minting logic
    }

    function pause() external onlyRole(PAUSER_ROLE) {
        // pause logic
    }
}
