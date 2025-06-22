import "@openzeppelin/contracts/security/Pausable.sol";

contract InfoSecAvailability is Pausable {
    function pause() external {
        _pause(); // Owner-only in real-world
    }

    function unpause() external {
        _unpause();
    }

    function protectedAction() external whenNotPaused {
        // Execute only if contract is active
    }
}
