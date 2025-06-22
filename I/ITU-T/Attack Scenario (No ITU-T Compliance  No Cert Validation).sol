pragma solidity ^0.8.21;

contract FakeKYC {
    mapping(address => string) public identity;

    function register(string memory fakeData) external {
        identity[msg.sender] = fakeData; // no verification at all
    }
}
