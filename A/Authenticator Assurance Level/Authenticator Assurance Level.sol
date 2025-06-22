// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Attack Types: Low Assurance Bypass Attack, Forgery of Authentication Level, Replay Attack on Authentication Tokens
/// Defense Types: Strict AAL Enforcement, Bound Authentication Proofs, Real-Time Challenge-Response

contract AuthenticatorAssuranceLevelSystem {
    address public admin;

    enum AAL { None, AAL1, AAL2, AAL3 } // Authenticator Assurance Levels
    mapping(address => AAL) public userAALs;
    mapping(address => uint256) public lastAuthTimestamp; // Optional: track when authenticated

    event AALAssigned(address indexed user, AAL level);
    event AttackDetected(string reason);

    constructor() {
        admin = msg.sender;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin can assign AALs");
        _;
    }

    /// ATTACK Simulation: Unauthorized self-promotion of AAL
    function attackForgeAAL(AAL fakeAAL) external {
        userAALs[msg.sender] = fakeAAL;
    }

    /// DEFENSE: Admin assigns AAL securely
    function assignAAL(address user, AAL level) external onlyAdmin {
        require(level != AAL.None, "Cannot assign None");
        userAALs[user] = level;
        lastAuthTimestamp[user] = block.timestamp;
        emit AALAssigned(user, level);
    }

    /// DEFENSE: Access control based on required AAL
    function performActionWithRequiredAAL(AAL requiredLevel) external view returns (string memory) {
        require(userAALs[msg.sender] >= requiredLevel, "Insufficient assurance level");
        return "Action permitted based on assurance level.";
    }

    /// View user's assigned AAL
    function viewUserAAL(address user) external view returns (AAL level, uint256 lastAuthenticated) {
        return (userAALs[user], lastAuthTimestamp[user]);
    }
}
