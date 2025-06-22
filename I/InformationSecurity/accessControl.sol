import "@openzeppelin/contracts/access/Ownable.sol";

contract SecureVault is Ownable {
    function withdraw() external onlyOwner {
        // Only owner can withdraw funds
    }
}
