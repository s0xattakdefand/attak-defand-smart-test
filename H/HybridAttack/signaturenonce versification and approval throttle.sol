import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract HybridDefenseVault {
    using ECDSA for bytes32;

    mapping(address => uint256) public nonces;
    mapping(address => uint256) public approvalLimit;

    event Withdraw(address user, uint256 amount);

    function approveLimit(uint256 limit) external {
        approvalLimit[msg.sender] = limit;
    }

    function withdrawSigned(
        uint256 amount,
        uint256 nonce,
        bytes calldata sig
    ) external {
        require(nonces[msg.sender] == nonce, "Invalid nonce");
        bytes32 hash = keccak256(abi.encodePacked(msg.sender, amount, nonce)).toEthSignedMessageHash();
        address signer = hash.recover(sig);
        require(signer == msg.sender, "Invalid sig");

        require(amount <= approvalLimit[msg.sender], "Limit exceeded");
        nonces[msg.sender]++;
        emit Withdraw(msg.sender, amount);

        // Transfer logic omitted
    }
}
