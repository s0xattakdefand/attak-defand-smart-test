contract ResponsePreviewSim {
    struct Action {
        string kind;
        bytes4 selector;
        address target;
        string previewNote;
    }

    Action[] public log;

    event Simulated(string kind, address indexed target, bytes4 sel, string note);

    function simulateResponse(string calldata kind, address target, bytes4 sel, string calldata note) external {
        log.push(Action(kind, sel, target, note));
        emit Simulated(kind, target, sel, note);
    }

    function exportLog() external view returns (Action[] memory) {
        return log;
    }
}
