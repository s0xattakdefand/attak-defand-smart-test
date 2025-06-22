// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract AccessPointProvisioner {
    address public admin;
    mapping(bytes32 => bool) public approvedAPs;
    mapping(bytes32 => bool) public revokedAPs;

    event AccessPointApproved(bytes32 indexed hash, address approver);
    event AccessPointRevoked(bytes32 indexed hash, address revoker);
    event JoinRequestValidated(bytes32 indexed hash, bool success);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not authorized");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function approveAccessPoint(bytes32 apHash) external onlyAdmin {
        approvedAPs[apHash] = true;
        emit AccessPointApproved(apHash, msg.sender);
    }

    function revokeAccessPoint(bytes32 apHash) external onlyAdmin {
        revokedAPs[apHash] = true;
        emit AccessPointRevoked(apHash, msg.sender);
    }

    function validateJoinRequest(bytes32 apHash) external returns (bool) {
        bool success = approvedAPs[apHash] && !revokedAPs[apHash];
        emit JoinRequestValidated(apHash, success);
        return success;
    }
}
