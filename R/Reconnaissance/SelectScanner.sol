contract SelectorScanner {
    event Probed(address target, bytes4 selector, bool success);

    function probe(address target, bytes4 selector) public {
        (bool ok, ) = target.call(abi.encodePacked(selector));
        emit Probed(target, selector, ok);
    }

    function scan(address target, uint8 rounds) public {
        for (uint8 i = 0; i < rounds; i++) {
            bytes4 sel = bytes4(keccak256(abi.encodePacked(target, block.number, i)));
            probe(target, sel);
        }
    }
}
