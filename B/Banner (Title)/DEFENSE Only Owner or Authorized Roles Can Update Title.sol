// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SecureBanner {
    string public banner;
    address public owner;

    event BannerUpdated(string newBanner);

    constructor(string memory defaultBanner) {
        owner = msg.sender;
        banner = defaultBanner;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not authorized");
        _;
    }

    function updateBanner(string calldata newBanner) public onlyOwner {
        banner = newBanner;
        emit BannerUpdated(newBanner);
    }

    function transferOwnership(address newOwner) public onlyOwner {
        owner = newOwner;
    }
}
