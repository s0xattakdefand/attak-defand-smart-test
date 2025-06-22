contract FallbackAuditor {
    event UnexpectedSelector(bytes4 sel);

    fallback() external {
        emit UnexpectedSelector(msg.sig);
        revert("Unexpected fallback");
    }
}
