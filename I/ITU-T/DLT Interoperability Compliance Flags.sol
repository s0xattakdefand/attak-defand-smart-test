pragma solidity ^0.8.21;

contract DLTInteropCompliance {
    mapping(address => bool) public compliantNodes;

    address public admin;
    event NodeMarked(address node, bool compliant);

    constructor() {
        admin = msg.sender;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    function setCompliance(address node, bool status) external onlyAdmin {
        compliantNodes[node] = status;
        emit NodeMarked(node, status);
    }

    function accessDLTResource() external view returns (string memory) {
        require(compliantNodes[msg.sender], "Not compliant per FG-DLT");
        return "Access granted to interoperable DLT system";
    }
}
