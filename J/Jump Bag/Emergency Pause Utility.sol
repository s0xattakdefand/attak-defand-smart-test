pragma solidity ^0.8.21;

import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract EmergencyPausable is Pausable, Ownable {
    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }

    function criticalFunction() external whenNotPaused {
        // Protected logic here
    }
}
