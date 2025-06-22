// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract AccessPointRegistry {
    enum APNType { PUBLIC, PRIVATE, ZK_ONLY, RELAYER }

    struct APNProfile {
        APNType apnType;
        string label;
        address[] members;
        mapping(address => bool) isMember;
    }

    mapping(bytes32 => APNProfile) private apnRegistry;
    mapping(address => bytes32) public userAPN;

    event APNCreated(bytes32 apnId, string label, APNType apnType);
    event UserAssigned(address user, bytes32 apnId);
    event APNAccessUsed(address user, string action, bytes32 apnId);

    modifier onlyAPN(bytes32 apnId) {
        require(userAPN[msg.sender] == apnId, "APN mismatch");
        require(apnRegistry[apnId].isMember[msg.sender], "Not authorized for this APN");
        _;
        emit APNAccessUsed(msg.sender, "exec", apnId);
    }

    function createAPN(bytes32 apnId, string calldata label, APNType apnType, address[] calldata members) external {
        APNProfile storage apn = apnRegistry[apnId];
        apn.apnType = apnType;
        apn.label = label;

        for (uint i = 0; i < members.length; i++) {
            apn.members.push(members[i]);
            apn.isMember[members[i]] = true;
        }

        emit APNCreated(apnId, label, apnType);
    }

    function assignUserToAPN(address user, bytes32 apnId) external {
        require(apnRegistry[apnId].isMember[user], "Not in APN list");
        userAPN[user] = apnId;
        emit UserAssigned(user, apnId);
    }

    function securedFunction(bytes32 apnId) external onlyAPN(apnId) {
        // Core logic protected by APN profile
    }

    function getUserAPN(address user) external view returns (string memory label, APNType apnType) {
        bytes32 apnId = userAPN[user];
        APNProfile storage apn = apnRegistry[apnId];
        return (apn.label, apn.apnType);
    }
}
