pragma solidity ^0.8.21;

contract LKMKernel {
    address public admin;
    mapping(bytes4 => address) public modules;

    constructor() {
        admin = msg.sender;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    function loadModule(bytes4 selector, address moduleAddr) external onlyAdmin {
        modules[selector] = moduleAddr;
    }

    fallback() external payable {
        address module = modules[msg.sig];
        require(module != address(0), "No module for function");
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), module, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
                case 0 { revert(0, returndatasize()) }
                default { return(0, returndatasize()) }
        }
    }
}
