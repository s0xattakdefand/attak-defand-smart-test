// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract DataCopySecure {
    address public admin;

    struct Profile {
        string name;
        uint256 age;
        string role;
    }

    mapping(address => Profile) private profiles;

    event ProfileUpdated(address indexed user, string name, uint256 age, string role);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not authorized");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    // Safely update a user's profile
    function updateProfile(string memory _name, uint256 _age, string memory _role) external {
        profiles[msg.sender] = Profile(_name, _age, _role);
        emit ProfileUpdated(msg.sender, _name, _age, _role);
    }

    // Safe deep copy from storage to memory, view only
    function getMyProfileCopy() external view returns (string memory, uint256, string memory) {
        Profile memory copy = _deepCopy(profiles[msg.sender]);
        return (copy.name, copy.age, copy.role);
    }

    // Admin can view any profile securely
    function viewUserProfile(address user) external view onlyAdmin returns (string memory, uint256, string memory) {
        Profile memory copy = _deepCopy(profiles[user]);
        return (copy.name, copy.age, copy.role);
    }

    // Internal deep copy to avoid storage reference bugs
    function _deepCopy(Profile storage input) internal view returns (Profile memory) {
        return Profile(input.name, input.age, input.role);
    }
}
