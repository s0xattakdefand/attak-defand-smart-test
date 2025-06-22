contract MutationPatternTracker {
    struct Mutation {
        bytes4 selector;
        uint256 time;
        address origin;
    }

    Mutation[] public history;

    event Mutated(bytes4 selector, address origin);

    function log(bytes4 selector) external {
        history.push(Mutation(selector, block.timestamp, tx.origin));
        emit Mutated(selector, tx.origin);
    }

    function getRecent(uint256 limit) external view returns (Mutation[] memory recent) {
        uint256 len = history.length;
        uint256 start = len > limit ? len - limit : 0;
        recent = new Mutation[](len - start);
        for (uint256 i = start; i < len; i++) {
            recent[i - start] = history[i];
        }
    }
}
