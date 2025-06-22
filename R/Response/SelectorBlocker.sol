contract SelectorBlocker {
    mapping(bytes4 => bool) public blocked;

    event SelectorBlocked(bytes4);

    function blockSelector(bytes4 sel) external {
        blocked[sel] = true;
        emit SelectorBlocked(sel);
    }

    modifier check(bytes4 sel) {
        require(!blocked[sel], "Blocked selector");
        _;
    }
}
