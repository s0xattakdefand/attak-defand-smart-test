import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract OctetHasher {
    using ECDSA for bytes32;

    function getHash(bytes calldata input) external pure returns (bytes32 hash, bytes memory octets) {
        hash = keccak256(input);
        octets = abi.encodePacked(hash); // 32 octets
    }

    function extractOctet(bytes32 hash, uint256 index) external pure returns (uint8) {
        require(index < 32, "Out of range");
        return uint8(bytes1(hash << (index * 8)));
    }
}
