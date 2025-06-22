pragma solidity ^0.8.21;

contract GeoTaggedPolicy {
    mapping(address => string) public regionTag;
    mapping(string => bool) public allowedRegions;
    address public admin;

    constructor() {
        admin = msg.sender;
        allowedRegions["KH"] = true;
    }

    modifier regionAllowed() {
        require(allowedRegions[regionTag[msg.sender]], "Region not allowed");
        _;
    }

    function setRegion(address user, string memory tag) external {
        require(msg.sender == admin, "Only admin");
        regionTag[user] = tag;
    }

    function regionRestrictedAction() external regionAllowed {
        // Region-controlled logic
    }
}
