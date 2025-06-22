// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";

contract ConfigurableModule is AccessControl {
    bytes32 public constant CONFIG_ADMIN = keccak256("CONFIG_ADMIN");

    uint256 public feePercent;
    address public oracle;
    uint256 public maxWithdrawal;

    event ConfigChanged(string param, bytes32 oldVal, bytes32 newVal);

    constructor() {
        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _setupRole(CONFIG_ADMIN, msg.sender);

        // Default config
        feePercent = 500; // 5%
        maxWithdrawal = 100 ether;
    }

    modifier onlyConfigAdmin() {
        require(hasRole(CONFIG_ADMIN, msg.sender), "Not config admin");
        _;
    }

    function updateFee(uint256 newFee) external onlyConfigAdmin {
        emit ConfigChanged("feePercent", bytes32(feePercent), bytes32(newFee));
        feePercent = newFee;
    }

    function updateOracle(address newOracle) external onlyConfigAdmin {
        emit ConfigChanged("oracle", bytes32(uint256(uint160(oracle))), bytes32(uint256(uint160(newOracle))));
        oracle = newOracle;
    }

    function updateMaxWithdrawal(uint256 newMax) external onlyConfigAdmin {
        emit ConfigChanged("maxWithdrawal", bytes32(maxWithdrawal), bytes32(newMax));
        maxWithdrawal = newMax;
    }
}
