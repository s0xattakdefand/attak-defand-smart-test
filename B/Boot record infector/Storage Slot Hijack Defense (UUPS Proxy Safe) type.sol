import "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract SafeUUPSProxy is UUPSUpgradeable, Ownable {
    function _authorizeUpgrade(address) internal override onlyOwner {}

    function safeLogic() external view returns (string memory) {
        return "All clear, no infection";
    }
}
