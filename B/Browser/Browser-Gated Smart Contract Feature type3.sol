contract BrowserOnlyFeature {
    address public frontend;
    mapping(address => uint256) public used;

    constructor(address _frontend) {
        frontend = _frontend;
    }

    function browserGateAction(uint256 nonce, bytes calldata sig) public {
        require(used[msg.sender] < nonce, "Nonce used");

        bytes32 hash = keccak256(abi.encodePacked(msg.sender, nonce)).toEthSignedMessageHash();
        require(hash.recover(sig) == frontend, "Not signed by frontend");

        used[msg.sender] = nonce;
        // run gated action
    }
}
