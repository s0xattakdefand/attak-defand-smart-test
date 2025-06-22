pragma solidity ^0.8.21;

contract L2TunnelBridge {
    address public relayer;
    mapping(bytes32 => bool) public processed;

    event MessageReceived(bytes32 indexed hash, address sender, bytes data);

    constructor(address _relayer) {
        relayer = _relayer;
    }

    function receiveMessage(bytes calldata data, bytes32 expectedHash) external {
        require(msg.sender == relayer, "Invalid relayer");
        require(!processed[expectedHash], "Replay detected");
        require(keccak256(data) == expectedHash, "Data hash mismatch");

        processed[expectedHash] = true;
        emit MessageReceived(expectedHash, msg.sender, data);

        // Continue with tunneled message execution...
    }
}
