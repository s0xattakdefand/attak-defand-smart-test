pragma solidity ^0.8.21;

contract AttributeAccessControl {
    struct Attributes {
        bool isHR;
        bool isAuditor;
    }

    mapping(address => Attributes) public userAttrs;

    function setAttributes(bool hr, bool auditor) external {
        userAttrs[msg.sender] = Attributes(hr, auditor);
    }

    function readPayroll() external view {
        require(userAttrs[msg.sender].isHR, "Only HR");
        // View payroll data
    }

    function auditLogs() external view {
        require(userAttrs[msg.sender].isAuditor, "Only Auditor");
        // View audit logs
    }
}
