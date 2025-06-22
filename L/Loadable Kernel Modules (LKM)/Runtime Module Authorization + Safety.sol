pragma solidity ^0.8.21;

contract SecureModuleLoader {
    address public admin;
    mapping(bytes4 => address) public modules;
    mapping(address => bool) public trustedModules;

    constructor() {
        admin = msg.sender;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin");
        _;
    }

    function authorizeModule(address module) external onlyAdmin {
        trustedModules[module] = true;
    }

    function load(bytes4 selector, address module) external onlyAdmin {
        require(trustedModules[module], "Untrusted module");
        modules[selector] = module;
    }
}
