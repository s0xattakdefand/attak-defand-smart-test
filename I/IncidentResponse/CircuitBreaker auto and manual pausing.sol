import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract EmergencyVault is Pausable, Ownable {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external whenNotPaused {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }

    function emergencyPause(string memory reason) external onlyOwner {
        _pause();
        emit IncidentDetected(msg.sender, Severity.Critical, reason);
    }

    function resume() external onlyOwner {
        _unpause();
    }
}
