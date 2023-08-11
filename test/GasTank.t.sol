// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.19 <0.9.0;

import { PRBTest } from "@prb/test/PRBTest.sol";
import { console2 } from "forge-std/console2.sol";
import { StdCheats } from "forge-std/StdCheats.sol";

import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { Safe } from "safe-contracts/contracts/Safe.sol";
import { SafeProxyFactory } from "safe-contracts/contracts/proxies/SafeProxyFactory.sol";
import { Enum } from "safe-contracts/contracts/common/Enum.sol";
import { ModuleManager } from "safe-contracts/contracts/base/ModuleManager.sol";

import { ERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import { Address } from "@openzeppelin/contracts/utils/Address.sol";

import { GasTank } from "../src/GasTank.sol";

interface IGelatoRelayERC2771 {
    struct CallWithERC2771 {
        uint256 chainId;
        address target;
        bytes data;
        address user;
        uint256 userNonce;
        uint256 userDeadline;
    }

    function userNonce(address user) external view returns (uint256);

    function DOMAIN_SEPARATOR() external view returns (bytes32);

    function callWithSyncFeeERC2771(
        CallWithERC2771 calldata _call,
        address _feeToken,
        bytes calldata _userSignature,
        bool _isRelayContext,
        bytes32 _correlationId
    )
        external;
}

contract GasTankTest is PRBTest, StdCheats {
    using EnumerableSet for EnumerableSet.AddressSet;

    GasTank internal gasTank;

    address public GELATO = 0x3CACa7b48D0573D793d3b0279b5F0029180E83b6;
    address public USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address public DAI = 0x6B175474E89094C44Da98b954EedeAC495271d0F;

    uint256 public kakarotoKey = 2;
    address public kakaroto = vm.addr(kakarotoKey);

    uint256 public karpinchoKey = 3;
    address public karpincho = vm.addr(karpinchoKey);

    uint256 public vegetaKey = 4;
    address public vegeta = vm.addr(vegetaKey);

    uint256 public feeCollectorKey = 5;
    address public feeCollector = vm.addr(feeCollectorKey);

    IGelatoRelayERC2771 public gelatoRelay = IGelatoRelayERC2771(0xBf175FCC7086b4f9bd59d5EAE8eA67b8f940DE0d);

    uint256 public constant USDC_UNIT = 10 ** 6;
    uint256 constant USDC_FEE = 100_000;
    uint256 constant DAI_FEE = 100_000_000_000_000_000;

    // Safe 1.4.1
    address public gnosisSafeTemplate = 0x41675C099F32341bf84BFc5382aF534df5C7461a; // G:9134480, M:17487000
    address public compatibilityFallbackHandler = 0xfd0732Dc9E303f09fCEf3a7388Ad10A83459Ec99; // G:9134477, M:17486892
    SafeProxyFactory public gnosisSafeProxyFactory = SafeProxyFactory(0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67); // G:8681525,
        // M:17440707

    address public safeProxy;
    Safe public theSafe;

    bytes32 public constant CALL_WITH_SYNC_FEE_ERC2771_TYPEHASH = keccak256(
        bytes(
            // solhint-disable-next-line max-line-length
            "CallWithSyncFeeERC2771(uint256 chainId,address target,bytes data,address user,uint256 userNonce,uint256 userDeadline)"
        )
    );

    mapping(address delegate => EnumerableSet.AddressSet[]) internal tokens;

    function getSignature(bytes memory toSign, uint256 key) public pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 _s) = vm.sign(key, ECDSA.toEthSignedMessageHash(toSign));
        return abi.encodePacked(r, _s, v);
    }

    function getSignature(bytes32 toSign, uint256 key) public pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 _s) = vm.sign(key, ECDSA.toEthSignedMessageHash(toSign));
        return abi.encodePacked(r, _s, v);
    }

    function setUp() public virtual {
        gasTank = new GasTank();

        address[] memory owners = new address[](2);
        owners[0] = kakaroto;
        owners[1] = karpincho;

        // configure safe owners and threshold
        bytes memory initializer = abi.encodeWithSelector(
            Safe.setup.selector,
            owners,
            1,
            address(0),
            new bytes(0),
            compatibilityFallbackHandler,
            address(0),
            0,
            payable(address(0))
        );

        // deploy safe
        safeProxy = address(gnosisSafeProxyFactory.createProxyWithNonce(gnosisSafeTemplate, initializer, 1));
        theSafe = Safe(payable(safeProxy));

        // set gastTank as SafeModule
        bytes memory payload = abi.encodeWithSelector(ModuleManager.enableModule.selector, address(gasTank));
        bytes32 txHash = theSafe.getTransactionHash(
            // Transaction info
            safeProxy,
            0,
            payload,
            Enum.Operation.Call,
            0,
            // Payment info
            0,
            0,
            address(0),
            payable(0),
            // Signature info
            theSafe.nonce()
        );

        (uint8 v, bytes32 r, bytes32 _s) = vm.sign(kakarotoKey, txHash);

        theSafe.execTransaction(
            safeProxy, 0, payload, Enum.Operation.Call, 0, 0, 0, address(0), payable(0), abi.encodePacked(r, _s, v)
        );

        // fund safe with some Goerli USDC, ETH or any other token Gelato accepts as Fee token
        deal(USDC, kakaroto, 10_000 ether, true);
        deal(USDC, safeProxy, 10_000 ether, true);
        deal(DAI, kakaroto, 10_000 ether, true);
        deal(DAI, safeProxy, 10_000 ether, true);
    }

    function test_execTransaction_should_work() external {
        uint256 safeUSDCBalanceBefore = ERC20(USDC).balanceOf(safeProxy);
        uint256 vegetaUSDCBalanceBefore = ERC20(USDC).balanceOf(vegeta);
        uint256 safeDAIBalanceBefore = ERC20(DAI).balanceOf(safeProxy);
        uint256 feeCollectorDAIBalanceBefore = ERC20(DAI).balanceOf(feeCollector);

        // build safe transaction for transferring USDC to some address
        bytes memory safePayload = getSafePayload();

        // owner signs fee approval
        bytes32 feeTxHash = gasTank.generateTransferHash(
            safeProxy, DAI, address(gasTank), 2, gasTank.ownerNonces(safeProxy, kakaroto)
        );
        (uint8 fee_v, bytes32 fee_r, bytes32 fee_s) = vm.sign(kakarotoKey, feeTxHash);
        bytes memory ownerFeeSig = abi.encodePacked(fee_r, fee_s, fee_v);
        bytes memory feeSignature = abi.encode(DAI, 2, ownerFeeSig);

        // build Gelato transaction
        bytes memory gasTankData =
            abi.encodeWithSelector(GasTank.execTransaction.selector, true, safeProxy, safePayload, feeSignature);
        bytes memory gelatoData = getGeletoData(gasTankData, 1, DAI, kakaroto, kakarotoKey);

        // execute
        vm.prank(GELATO);
        Address.functionCall(address(gelatoRelay), gelatoData);

        assertEq(ERC20(USDC).balanceOf(safeProxy), safeUSDCBalanceBefore - 10);
        assertEq(ERC20(USDC).balanceOf(vegeta), vegetaUSDCBalanceBefore + 10);
        assertEq(ERC20(DAI).balanceOf(safeProxy), safeDAIBalanceBefore - 1);
        assertEq(ERC20(DAI).balanceOf(feeCollector), feeCollectorDAIBalanceBefore + 1);
    }

    function getSafePayload() internal view returns (bytes memory) {
        // owner sings safe transaction
        bytes memory erc20TransferPayload = abi.encodeWithSelector(ERC20.transfer.selector, vegeta, 10);
        bytes32 txHash = theSafe.getTransactionHash(
            // Transaction info
            USDC,
            0,
            erc20TransferPayload,
            Enum.Operation.Call,
            0,
            // Payment info
            0,
            0,
            address(0),
            payable(0),
            // Signature info
            theSafe.nonce()
        );
        (uint8 v, bytes32 r, bytes32 _s) = vm.sign(kakarotoKey, txHash);

        // build safe transaction for transferring USDC to some address
        return abi.encodeWithSelector(
            Safe.execTransaction.selector,
            USDC,
            0,
            erc20TransferPayload,
            Enum.Operation.Call,
            0,
            0,
            0,
            address(0),
            payable(0),
            abi.encodePacked(r, _s, v)
        );
    }

    function getGeletoData(
        bytes memory gtData,
        uint256 fee,
        address payToken,
        address sender,
        uint256 senderKey
    )
        internal
        view
        returns (bytes memory)
    {
        IGelatoRelayERC2771.CallWithERC2771 memory call = IGelatoRelayERC2771.CallWithERC2771(
            block.chainid, address(gasTank), gtData, sender, gelatoRelay.userNonce(sender), 0
        );

        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                gelatoRelay.DOMAIN_SEPARATOR(),
                keccak256(
                    abi.encode(
                        CALL_WITH_SYNC_FEE_ERC2771_TYPEHASH,
                        call.chainId,
                        call.target,
                        keccak256(call.data),
                        call.user,
                        call.userNonce,
                        call.userDeadline
                    )
                )
            )
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(senderKey, digest);
        bytes memory senderSig = abi.encodePacked(r, s, v);

        bytes memory data = abi.encodeWithSelector(
            IGelatoRelayERC2771.callWithSyncFeeERC2771.selector, call, payToken, senderSig, true, bytes32(0)
        );

        return abi.encodePacked(data, feeCollector, payToken, fee);
    }
}
