import "./ARX.sol";

contract EntropyMixer {
    using ARX for uint256;

    function getEntropy(uint256 base) external pure returns (uint256) {
        return ARX.arxHash(base);
    }
}
