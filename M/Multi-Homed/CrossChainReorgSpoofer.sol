interface IZKRouteVerifier {
    function verify(bytes calldata zkProof, bytes32 input) external view returns (bool);
}
interface IMOEManager {
    function logChainRoute(uint256 chainId, bool ok) external;
}

contract CrossChainReorgSpoofer {
    IZKRouteVerifier public verifier;
    IMOEManager public moelog;
    MultiBridgeRouter public router;

    constructor(address _router, address _verifier, address _moe) {
        router = MultiBridgeRouter(_router);
        verifier = IZKRouteVerifier(_verifier);
        moelog = IMOEManager(_moe);
    }

    function spoofRoute(
        uint256 chainId,
        bytes calldata payload,
        bytes calldata zkProof,
        bytes32 input
    ) external {
        bool verified = verifier.verify(zkProof, input);
        bool ok;

        if (verified) {
            try router.routeFromChain(chainId, payload) {
                ok = true;
            } catch {
                ok = false;
            }
        }

        moelog.logChainRoute(chainId, ok);
    }
}
