import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract InfoSecSignature {
    using ECDSA for bytes32;

    mapping(address => bool) public approved;

    function verify(address user, bytes calldata sig) external {
        bytes32 hash = keccak256(abi.encodePacked(user)).toEthSignedMessageHash();
        require(hash.recover(sig) == user, "Invalid signature");
        approved[user] = true;
    }
}
