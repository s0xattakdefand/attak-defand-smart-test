interface IEntropyABIEnhancer {
    function label(bytes4 selector, string calldata guess, uint8 entropy, bool confirmed) external;
}

contract AutoSimExecutor {
    IEntropyABIEnhancer public enhancer;
    address public target;

    constructor(address _enhancer, address _target) {
        enhancer = IEntropyABIEnhancer(_enhancer);
        target = _target;
    }

    function simulateReplay(bytes32 seed, uint256 rounds) external {
        for (uint256 i = 0; i < rounds; i++) {
            bytes4 sel = bytes4(keccak256(abi.encodePacked(seed, i)));
            uint8 ent = entropy(sel);
            (bool ok, ) = target.call(abi.encodePacked(sel));
            enhancer.label(sel, string.concat("guess_", toHex(sel)), ent, ok);
        }
    }

    function entropy(bytes4 sel) public pure returns (uint8 score) {
        uint32 x = uint32(sel);
        while (x != 0) { score++; x &= (x - 1); }
    }

    function toHex(bytes4 data) internal pure returns (string memory) {
        bytes memory alphabet = "0123456789abcdef";
        bytes memory str = new bytes(10);
        str[0] = '0'; str[1] = 'x';
        for (uint i = 0; i < 4; i++) {
            str[2 + i * 2] = alphabet[uint(uint8(data[i] >> 4))];
            str[3 + i * 2] = alphabet[uint(uint8(data[i] & 0x0f))];
        }
        return string(str);
    }
}
