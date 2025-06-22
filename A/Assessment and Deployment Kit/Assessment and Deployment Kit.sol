// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Web3 Assessment and Deployment Kit (ADK)
contract AssessmentDeploymentKit {
    address public admin;

    struct Assessment {
        bool passed;
        string reason;
    }

    mapping(address => Assessment) public assessments;

    event Assessed(address candidate, bool passed, string reason);
    event Deployed(address indexed creator, address deployed);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    /// Simulate/assess input config
    function assessCandidate(address candidate, bool pass, string calldata reason) external onlyAdmin {
        assessments[candidate] = Assessment(pass, reason);
        emit Assessed(candidate, pass, reason);
    }

    /// Deploy if assessment passed
    function deploy(bytes memory bytecode, bytes32 salt) external returns (address addr) {
        require(assessments[msg.sender].passed, "Assessment failed");

        assembly {
            addr := create2(0, add(bytecode, 0x20), mload(bytecode), salt)
            if iszero(extcodesize(addr)) { revert(0, 0) }
        }

        emit Deployed(msg.sender, addr);
    }

    /// Dry-run address prediction
    function computeAddress(bytes memory bytecode, bytes32 salt) external view returns (address) {
        return address(uint160(uint256(
            keccak256(abi.encodePacked(bytes1(0xff), address(this), salt, keccak256(bytecode)))
        )));
    }
}
