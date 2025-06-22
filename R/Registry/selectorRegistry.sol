contract SelectorRegistry {
    mapping(bytes4 => bool) public registered;
    event SelectorAdded(bytes4 selector);
    event SelectorRemoved(bytes4 selector);

    function add(bytes4 sel) external {
        registered[sel] = true;
        emit SelectorAdded(sel);
    }

    function remove(bytes4 sel) external {
        registered[sel] = false;
        emit SelectorRemoved(sel);
    }
}
