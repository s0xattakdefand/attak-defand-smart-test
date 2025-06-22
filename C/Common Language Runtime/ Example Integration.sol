// A Solidity module (can be Huff, Yul, Vyper underneath)
contract MathLib {
    function add(uint256 a, uint256 b) external pure returns (uint256) {
        return a + b;
    }
}

// Register into CLREngine
clr.registerModule(
    keccak256("MathAddModule"),
    address(mathLib),
    "Solidity",
    type(IMath).interfaceId
);

// Call via CLREngine
clr.executeModule(
    keccak256("MathAddModule"),
    abi.encodeWithSignature("add(uint256,uint256)", 5, 7)
);
