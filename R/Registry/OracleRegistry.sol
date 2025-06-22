contract OracleRegistry {
    mapping(address => bool) public approvedFeeds;
    event OracleApproved(address feed);
    event OracleRevoked(address feed);

    function approve(address feed) external {
        approvedFeeds[feed] = true;
        emit OracleApproved(feed);
    }

    function revoke(address feed) external {
        approvedFeeds[feed] = false;
        emit OracleRevoked(feed);
    }
}
