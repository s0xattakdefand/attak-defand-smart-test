contract ZombieContractEcho {
    event Echo(bytes data);

    fallback() external payable {
        emit Echo(msg.data);
    }
}
