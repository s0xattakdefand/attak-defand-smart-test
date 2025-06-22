// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VulnerableBanner {
    string public banner;

    constructor() {
        banner = "Welcome to the DAO!";
    }

    // ❌ Anyone can change the title/banner
    function updateBanner(string calldata newBanner) public {
        banner = newBanner;
    }
}
