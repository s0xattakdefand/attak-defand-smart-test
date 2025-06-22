contract MaskedProxy {
    address public backend;

    constructor(address _backend) {
        backend = _backend;
    }

    fallback() external payable {
        bytes memory wrapped = abi.encodeWithSelector(
            msg.sig,
            msg.sender,
            msg.data
        );
        (bool ok, bytes memory result) = backend.delegatecall(wrapped);
        require(ok, "Failed");
        assembly { return(add(result, 32), mload(result)) }
    }
}
