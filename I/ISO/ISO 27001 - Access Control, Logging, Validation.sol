pragma solidity ^0.8.21;

import "@openzeppelin/contracts/access/AccessControl.sol";

contract ISO27001SecureTransfer is AccessControl {
    bytes32 public constant USER_ROLE = keccak256("USER_ROLE");

    mapping(address => uint256) public balances;
    event TransferPerformed(address from, address to, uint256 amount);

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(USER_ROLE, msg.sender);
    }

    function deposit() external payable onlyRole(USER_ROLE) {
        balances[msg.sender] += msg.value;
    }

    function transfer(address to, uint256 amount) external onlyRole(USER_ROLE) {
        require(balances[msg.sender] >= amount, "Insufficient funds");
        balances[msg.sender] -= amount;
        balances[to] += amount;

        emit TransferPerformed(msg.sender, to, amount);
    }
}
