// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IConceptLogic {
    function run(uint256 input) external pure returns (uint256);
}

// Dynamic Logic Type - Safe Logic
contract DoubleLogic is IConceptLogic {
    function run(uint256 input) external pure override returns (uint256) {
        return input * 2;
    }
}

// Dynamic Logic Type - Malicious Logic
contract ZeroLogic is IConceptLogic {
    function run(uint256 input) external pure override returns (uint256) {
        return 0;
    }
}

// ConceptType Manager Contract
contract ConceptType {
    address public owner;
    address public logic;
    mapping(address => bool) public roleAdmin;

    event LogicExecuted(uint256 input, uint256 output);
    event LogicUpgraded(address newLogic);
    event RoleSet(address indexed user, bool admin);

    constructor(address _logic) {
        owner = msg.sender;
        logic = _logic;
        roleAdmin[owner] = true;
    }

    modifier onlyAdmin() {
        require(roleAdmin[msg.sender], "Not authorized");
        _;
    }

    function setRole(address user, bool isAdmin) external onlyAdmin {
        roleAdmin[user] = isAdmin;
        emit RoleSet(user, isAdmin);
    }

    function upgradeLogic(address _newLogic) external onlyAdmin {
        require(_newLogic.code.length > 0, "Invalid logic address");
        logic = _newLogic;
        emit LogicUpgraded(_newLogic);
    }

    function execute(uint256 input) external returns (uint256) {
        uint256 output = IConceptLogic(logic).run(input);
        emit LogicExecuted(input, output);
        return output;
    }

    // Static concept lock
    address public immutable conceptAnchor = address(this);
}
