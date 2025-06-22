pragma solidity ^0.8.21;

contract GeoIPAccessControl {
    address public admin;

    mapping(address => string) public region;
    mapping(string => bool) public allowedRegions;

    event AccessGranted(address user, string regionCode);

    constructor() {
        admin = msg.sender;
        allowedRegions["KH"] = true; // Cambodia
        allowedRegions["SG"] = true; // Singapore
    }

    function setRegion(address user, string memory regionCode) external {
        require(msg.sender == admin, "Only admin");
        region[user] = regionCode;
    }

    function setAllowed(string memory regionCode, bool allowed) external {
        require(msg.sender == admin, "Only admin");
        allowedRegions[regionCode] = allowed;
    }

    function geoProtectedAction() external {
        string memory userRegion = region[msg.sender];
        require(allowedRegions[userRegion], "Region access denied");
        emit AccessGranted(msg.sender, userRegion);
        // Execute region-restricted logic
    }
}
