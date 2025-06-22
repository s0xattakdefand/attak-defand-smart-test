interface IWrappedToken {
    function burnFrom(address account, uint256 amount) external;
    function mint(address account, uint256 amount) external;
}

contract BurnReleaseBridge {
    IWrappedToken public wrapped;
    address public signer;
    mapping(bytes32 => bool) public processed;

    constructor(address _wrapped, address _signer) {
        wrapped = IWrappedToken(_wrapped);
        signer = _signer;
    }

    function burnToBridge(uint256 amount, string calldata destination) public {
        wrapped.burnFrom(msg.sender, amount);
    }

    function releaseFromBridge(
        address user,
        uint256 amount,
        string calldata source,
        uint256 nonce,
        bytes calldata sig
    ) public {
        bytes32 hash = keccak256(abi.encodePacked(user, amount, source, nonce));
        require(!processed[hash], "Already processed");
        require(hash.toEthSignedMessageHash().recover(sig) == signer, "Invalid sig");

        processed[hash] = true;
        wrapped.mint(user, amount);
    }
}
