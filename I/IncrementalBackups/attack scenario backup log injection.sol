contract FakeBackupInjector {
    function injectFakeBackup(IncrementalBackupRegistry registry) external {
        // tries to overwrite historical logs
        registry.updateState("admin", "attacker");
    }
}
