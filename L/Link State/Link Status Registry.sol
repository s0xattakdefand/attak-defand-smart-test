pragma solidity ^0.8.21;

contract LinkStateRegistry {
    mapping(address => bool) public isActive;

    event LinkStatusUpdated(address indexed link, bool status);

    function updateLinkStatus(address link, bool active) external {
        isActive[link] = active;
        emit LinkStatusUpdated(link, active);
    }

    function checkLink(address link) external view returns (bool) {
        return isActive[link];
    }
}
