// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CORSAuth {
    address public admin;

    mapping(bytes32 => bool) public allowedOrigins; // keccak256(originURL)

    event OriginWhitelisted(bytes32 indexed originHash, string originURL);
    event ActionPerformed(address indexed user, string action);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function whitelistOrigin(string calldata originURL) external onlyAdmin {
        bytes32 hash = keccak256(abi.encodePacked(originURL));
        allowedOrigins[hash] = true;
        emit OriginWhitelisted(hash, originURL);
    }

    function doSomething(string calldata originURL, string calldata action) external {
        bytes32 hash = keccak256(abi.encodePacked(originURL));
        require(allowedOrigins[hash], "Origin not allowed");

        // Custom logic here
        emit ActionPerformed(msg.sender, action);
    }
}
