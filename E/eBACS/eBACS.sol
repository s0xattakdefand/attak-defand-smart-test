// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract eBACS {
    // Enum for benchmark types (e.g., encryption, signing)
    enum BenchmarkType { None, Encryption, Decryption, Signing, Verification, Hashing }

    // Structure for benchmark attestation
    struct Benchmark {
        address attester; // Trusted benchmarker (e.g., research institute)
        string algorithm; // Cryptographic algorithm (e.g., "AES-256")
        BenchmarkType bType; // Type of benchmark
        uint256 cyclesPerOperation; // Performance metric (cycles/op)
        string platform; // Hardware/software platform (e.g., "x86")
        bytes32 nonce; // Unique nonce to prevent replay/eavesdropping
        bool isValid; // Attestation status
        uint256 timestamp; // Creation time
    }

    // Mapping to store benchmarks by ID
    mapping(uint256 => Benchmark) public benchmarks;
    // Mapping to track authorized attesters
    mapping(address => bool) public authorizedAttesters;
    // Benchmark counter
    uint256 public benchmarkCount;
    // Admin address
    address public admin;

    // Events for user feedback
    event BenchmarkAttested(uint256 indexed benchmarkId, address indexed attester, string algorithm, BenchmarkType bType, uint256 cyclesPerOperation, string platform, bytes32 nonce);
    event BatchBenchmarkAttested(uint256[] benchmarkIds, address attester);
    event BenchmarkRevoked(uint256 indexed benchmarkId, address indexed attester);
    event AttesterAuthorized(address indexed attester, bool authorized);

    // Modifier to restrict to admin
    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin can perform this action");
        _;
    }

    // Modifier to restrict to authorized attesters
    modifier onlyAuthorizedAttester() {
        require(authorizedAttesters[msg.sender] || msg.sender == admin, "Not an authorized attester");
        _;
    }

    // Constructor to set admin
    constructor() {
        admin = msg.sender;
        benchmarkCount = 0;
    }

    // Function to authorize attesters
    function authorizeAttester(address _attester, bool _status) external onlyAdmin {
        authorizedAttesters[_attester] = _status;
        emit AttesterAuthorized(_attester, _status);
    }

    // Function to attest to a single benchmark
    function attestBenchmark(
        string calldata _algorithm,
        uint8 _bType,
        uint256 _cyclesPerOperation,
        string calldata _platform,
        bytes32 _nonce
    ) public onlyAuthorizedAttester returns (uint256) {
        require(bytes(_algorithm).length > 0, "Invalid algorithm");
        require(_bType >= 1 && _bType <= 5, "Invalid benchmark type (must be 1-5)");
        require(_cyclesPerOperation > 0, "Cycles per operation must be greater than zero");
        require(bytes(_platform).length > 0, "Invalid platform");
        require(_nonce != bytes32(0), "Invalid nonce");

        benchmarkCount++;
        benchmarks[benchmarkCount] = Benchmark({
            attester: msg.sender,
            algorithm: _algorithm,
            bType: BenchmarkType(_bType),
            cyclesPerOperation: _cyclesPerOperation,
            platform: _platform,
            nonce: _nonce,
            isValid: true,
            timestamp: block.timestamp
        });

        emit BenchmarkAttested(benchmarkCount, msg.sender, _algorithm, BenchmarkType(_bType), _cyclesPerOperation, _platform, _nonce);
        return benchmarkCount;
    }

    // Function to attest to multiple benchmarks (batch)
    function batchAttestBenchmarks(
        string[] calldata _algorithms,
        uint8[] calldata _bTypes,
        uint256[] calldata _cyclesPerOperations,
        string[] calldata _platforms,
        bytes32[] calldata _nonces
    ) external onlyAuthorizedAttester returns (uint256[] memory) {
        require(
            _algorithms.length == _bTypes.length &&
            _bTypes.length == _cyclesPerOperations.length &&
            _cyclesPerOperations.length == _platforms.length &&
            _platforms.length == _nonces.length,
            "Mismatched input arrays"
        );
        require(_algorithms.length > 0, "Empty batch");
        require(_algorithms.length <= 50, "Batch size too large"); // Gas limit safety

        uint256[] memory ids = new uint256[](_algorithms.length);

        for (uint256 i = 0; i < _algorithms.length; i++) {
            ids[i] = attestBenchmark(_algorithms[i], _bTypes[i], _cyclesPerOperations[i], _platforms[i], _nonces[i]);
        }

        emit BatchBenchmarkAttested(ids, msg.sender);
        return ids;
    }

    // Function to revoke a benchmark attestation
    function revokeBenchmark(uint256 _benchmarkId) external {
        require(_benchmarkId > 0 && _benchmarkId <= benchmarkCount, "Invalid benchmark ID");
        Benchmark storage benchmark = benchmarks[_benchmarkId];
        require(benchmark.attester == msg.sender || msg.sender == admin, "Not authorized to revoke");
        require(benchmark.isValid, "Benchmark already revoked");

        benchmark.isValid = false;
        emit BenchmarkRevoked(_benchmarkId, msg.sender);
    }

    // Function to verify a benchmark
    function verifyBenchmark(uint256 _benchmarkId) external view returns (string memory status, string memory algorithm, BenchmarkType bType) {
        require(_benchmarkId > 0 && _benchmarkId <= benchmarkCount, "Invalid benchmark ID");
        Benchmark memory benchmark = benchmarks[_benchmarkId];
        return (benchmark.isValid ? "Valid" : "Revoked", benchmark.algorithm, benchmark.bType);
    }

    // Function to get benchmark details
    function getBenchmark(uint256 _benchmarkId)
        external
        view
        returns (
            address attester,
            string memory algorithm,
            BenchmarkType bType,
            uint256 cyclesPerOperation,
            string memory platform,
            bytes32 nonce,
            bool isValid,
            uint256 timestamp
        )
    {
        require(_benchmarkId > 0 && _benchmarkId <= benchmarkCount, "Invalid benchmark ID");
        Benchmark memory benchmark = benchmarks[_benchmarkId];
        return (
            benchmark.attester,
            benchmark.algorithm,
            benchmark.bType,
            benchmark.cyclesPerOperation,
            benchmark.platform,
            benchmark.nonce,
            benchmark.isValid,
            benchmark.timestamp
        );
    }
}