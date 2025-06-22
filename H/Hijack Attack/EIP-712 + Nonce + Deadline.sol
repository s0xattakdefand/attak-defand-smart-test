import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract SafeClaim {
    using ECDSA for bytes32;

    mapping(address => uint256) public nonces;

    function claim(uint256 deadline, bytes calldata sig) external {
        require(block.timestamp < deadline, "Expired");

        bytes32 hash = keccak256(abi.encodePacked(msg.sender, nonces[msg.sender], deadline));
        bytes32 ethHash = hash.toEthSignedMessageHash();
        address signer = ethHash.recover(sig);

        require(signer == msg.sender, "Invalid sig");
        nonces[msg.sender]++;
    }
}
