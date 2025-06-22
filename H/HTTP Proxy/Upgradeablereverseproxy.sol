import "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract ReverseProxy is UUPSUpgradeable, Ownable {
    function _authorizeUpgrade(address newImpl) internal override onlyOwner {}
}
