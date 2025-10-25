// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract eBAEAD {
    // Enum for AEAD operations
    enum OperationType { None, Encryption, Decryption, Authentication }

    // Structure for AEAD benchmark attestation
    struct Benchmark {
        address attester; // Trusted benchmarker (e.g., eBAEAD contributor)
        string cipher; // AEAD cipher (e.g., "AES-GCM")
        OperationType opType; // Operation type
        uint256 cyclesPerByte; // Performance metric (cycles/byte)
        string platform; // Hardware platform (e.g., "x86-Skylake")
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
    event BenchmarkAttested(uint256 indexed benchmarkId, address indexed attester, string cipher, OperationType opType, uint256 cyclesPerByte, string platform, bytes32 nonce);
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

    // Function to attest to a single AEAD benchmark
    function attestBenchmark(
        string calldata _cipher,
        uint8 _opType,
        uint256 _cyclesPerByte,
        string calldata _platform,
        bytes32 _nonce
    ) public onlyAuthorizedAttester returns (uint256) {
        require(bytes(_cipher).length > 0, "Invalid cipher");
        require(_opType >= 1 && _opType <= 3, "Invalid operation type (must be 1-3)");
        require(_cyclesPerByte > 0, "Cycles per byte must be greater than zero");
        require(bytes(_platform).length > 0, "Invalid platform");
        require(_nonce != bytes32(0), "Invalid nonce");

        benchmarkCount++;
        benchmarks[benchmarkCount] = Benchmark({
            attester: msg.sender,
            cipher: _cipher,
            opType: OperationType(_opType),
            cyclesPerByte: _cyclesPerByte,
            platform: _platform,
            nonce: _nonce,
            isValid: true,
            timestamp: block.timestamp
        });

        emit BenchmarkAttested(benchmarkCount, msg.sender, _cipher, OperationType(_opType), _cyclesPerByte, _platform, _nonce);
        return benchmarkCount;
    }

    // Function to attest to multiple AEAD benchmarks (batch)
    function batchAttestBenchmarks(
        string[] calldata _ciphers,
        uint8[] calldata _opTypes,
        uint256[] calldata _cyclesPerBytes,
        string[] calldata _platforms,
        bytes32[] calldata _nonces
    ) external onlyAuthorizedAttester returns (uint256[] memory) {
        require(
            _ciphers.length == _opTypes.length &&
            _opTypes.length == _cyclesPerBytes.length &&
            _cyclesPerBytes.length == _platforms.length &&
            _platforms.length == _nonces.length,
            "Mismatched input arrays"
        );
        require(_ciphers.length > 0, "Empty batch");
        require(_ciphers.length <= 50, "Batch size too large"); // Gas limit safety

        uint256[] memory ids = new uint256[](_ciphers.length);

        for (uint256 i = 0; i < _ciphers.length; i++) {
            ids[i] = attestBenchmark(_ciphers[i], _opTypes[i], _cyclesPerBytes[i], _platforms[i], _nonces[i]);
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
    function verifyBenchmark(uint256 _benchmarkId) external view returns (string memory status, string memory cipher, OperationType opType) {
        require(_benchmarkId > 0 && _benchmarkId <= benchmarkCount, "Invalid benchmark ID");
        Benchmark memory benchmark = benchmarks[_benchmarkId];
        return (benchmark.isValid ? "Valid" : "Revoked", benchmark.cipher, benchmark.opType);
    }

    // Function to get benchmark details
    function getBenchmark(uint256 _benchmarkId)
        external
        view
        returns (
            address attester,
            string memory cipher,
            OperationType opType,
            uint256 cyclesPerByte,
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
            benchmark.cipher,
            benchmark.opType,
            benchmark.cyclesPerByte,
            benchmark.platform,
            benchmark.nonce,
            benchmark.isValid,
            benchmark.timestamp
        );
    }
}