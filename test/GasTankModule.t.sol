// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.21;

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

import { GasTankModule } from "../src/GasTankModule.sol";

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

contract GasTankModuleTest is PRBTest, StdCheats {
    GasTankModule internal gasTankModule;

    address public GELATO = 0x3CACa7b48D0573D793d3b0279b5F0029180E83b6;
    address public USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address public DAI = 0x6B175474E89094C44Da98b954EedeAC495271d0F;
    address public EL_DIEGO = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;

    uint256 public kakarotoKey = 2;
    address public kakaroto = vm.addr(kakarotoKey);

    uint256 public karpinchoKey = 3;
    address public karpincho = vm.addr(karpinchoKey);

    uint256 public vegetaKey = 4;
    address public vegeta = vm.addr(vegetaKey);

    uint256 public delegateKey = 5;
    address public delegate = vm.addr(delegateKey);

    uint256 public feeCollectorKey = 6;
    address public feeCollector = vm.addr(feeCollectorKey);

    uint256 public adminKey = 7;
    address public admin = vm.addr(adminKey);

    IGelatoRelayERC2771 public gelatoRelay = IGelatoRelayERC2771(0xb539068872230f20456CF38EC52EF2f91AF4AE49);

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

    address public safeExternalGTProxy;
    Safe public theSafeExternalGT;

    bytes32 public constant CALL_WITH_SYNC_FEE_ERC2771_TYPEHASH = keccak256(
        bytes(
            // solhint-disable-next-line max-line-length
            "CallWithSyncFeeERC2771(uint256 chainId,address target,bytes data,address user,uint256 userNonce,uint256 userDeadline)"
        )
    );

    event ExecutionFailure(bytes32 indexed txHash, uint256 payment);

    function getSignature(bytes memory toSign, uint256 key) public pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 _s) = vm.sign(key, ECDSA.toEthSignedMessageHash(toSign));
        return abi.encodePacked(r, _s, v);
    }

    function getSignature(bytes32 toSign, uint256 key) public pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 _s) = vm.sign(key, ECDSA.toEthSignedMessageHash(toSign));
        return abi.encodePacked(r, _s, v);
    }

    function deploySafe(address[] memory owners, uint256 threshold) internal returns (address) {
        // it enables the GasTank as module during creation of the Safe
        bytes memory moduleInitializer = abi.encodeWithSelector(GasTankModule.enableMyself.selector);

        // configure safe owners and threshold
        bytes memory initializer = abi.encodeWithSelector(
            Safe.setup.selector,
            owners,
            threshold,
            address(gasTankModule),
            moduleInitializer,
            compatibilityFallbackHandler,
            address(0),
            0,
            payable(address(0))
        );

        // deploy safe
        return address(gnosisSafeProxyFactory.createProxyWithNonce(gnosisSafeTemplate, initializer, 1));
    }

    function getTransactionHash(Safe safe, address to, bytes memory payload) internal view returns (bytes32) {
        return safe.getTransactionHash(
            // Transaction info
            to,
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
            safe.nonce()
        );
    }

    function execTransaction(
        Safe safe,
        address to,
        bytes memory payload,
        uint256 signerKey
    )
        internal
        returns (bool success)
    {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, getTransactionHash(safe, to, payload));

        return safe.execTransaction(
            to, 0, payload, Enum.Operation.Call, 0, 0, 0, address(0), payable(0), abi.encodePacked(r, s, v)
        );
    }

    // this could be used for enabling the module on a safe that is already created
    function enableModule(address module, Safe safe, uint256 signerKey) internal {
        // set gastTank as SafeModule
        bytes memory payload = abi.encodeWithSelector(ModuleManager.enableModule.selector, module);
        execTransaction(safe, address(safe), payload, signerKey);
    }

    function setUp() public virtual {
        // vm.prank(admin);
        gasTankModule = new GasTankModule(admin);

        address[] memory owners = new address[](2);
        owners[0] = kakaroto;
        owners[1] = karpincho;

        // deploy safe
        safeProxy = deploySafe(owners, 1);
        theSafe = Safe(payable(safeProxy));

        // set gastTank as SafeModule
        // enableModule(address(gasTank), theSafe, kakarotoKey);
        assertTrue(theSafe.isModuleEnabled(address(gasTankModule)));

        owners[0] = vegeta;

        // deploy safe
        safeExternalGTProxy = deploySafe(owners, 1);
        theSafeExternalGT = Safe(payable(safeExternalGTProxy));

        // set gastTank as SafeModule
        // enableModule(address(gasTankModule), theSafeExternalGT, vegetaKey);

        address[] memory allowedTokens = new address[](3);
        allowedTokens[0] = DAI;
        allowedTokens[1] = EL_DIEGO;
        allowedTokens[2] = address(0);
        setDelegateAndTokens(theSafeExternalGT, vegetaKey, delegate, allowedTokens);

        // fund safe with some Goerli USDC, ETH or any other token Gelato accepts as Fee token
        deal(USDC, kakaroto, 10_000 ether, true);
        deal(USDC, safeProxy, 10_000 ether, true);
        deal(USDC, safeExternalGTProxy, 10_000 ether, true);

        deal(safeProxy, 10 ether);
        deal(safeExternalGTProxy, 10 ether);

        deal(DAI, kakaroto, 10_000 ether, true);
        deal(DAI, safeProxy, 10_000 ether, true);
        deal(DAI, safeExternalGTProxy, 10_000 ether, true);
    }

    function test_DOMAIN_SEPARATOR() external view {
        gasTankModule.DOMAIN_SEPARATOR();
    }

    function test_enableMyself_notDELEGATECALL() external {
        vm.expectRevert(GasTankModule.GasTankModule__enableMyself_notDELEGATECALL.selector);
        gasTankModule.enableMyself();
    }

    function test_enableMyself_twice() external {
        bytes memory payload = abi.encodeWithSelector(GasTankModule.enableMyself.selector);
        bytes32 txHash = theSafe.getTransactionHash(
            // Transaction info
            address(gasTankModule),
            0,
            payload,
            Enum.Operation.DelegateCall,
            0,
            // Payment info
            0,
            0,
            address(0),
            payable(0),
            // Signature info
            theSafe.nonce()
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(kakarotoKey, txHash);

        // Internally it reverts with GS102
        // You can use vvvv to prove I'm right :-P
        vm.expectRevert("GS013");
        theSafe.execTransaction(
            address(gasTankModule),
            0,
            payload,
            Enum.Operation.DelegateCall,
            0,
            0,
            0,
            address(0),
            payable(0),
            abi.encodePacked(r, s, v)
        );
    }

    function test_withdraw_onlyOwner() external {
        vm.prank(vegeta);
        vm.expectRevert("Ownable: caller is not the owner");
        gasTankModule.withdraw(USDC, vegeta);
    }

    function test_withdraw_should_work_ERC20() external {
        deal(USDC, address(gasTankModule), 10, true);
        uint256 gasTankModuleUSDCBalanceBefore = ERC20(USDC).balanceOf(address(gasTankModule));
        uint256 adminUSDCBalanceBefore = ERC20(USDC).balanceOf(admin);

        vm.prank(admin);
        gasTankModule.withdraw(USDC, admin);

        assertEq(ERC20(USDC).balanceOf(address(gasTankModule)), gasTankModuleUSDCBalanceBefore - 10);
        assertEq(ERC20(USDC).balanceOf(admin), adminUSDCBalanceBefore + 10);
    }

    function test_withdraw_should_work_ETH() external {
        deal(address(gasTankModule), 10);
        uint256 gasTankModuleETHBalanceBefore = address(gasTankModule).balance;
        uint256 adminETHBalanceBefore = admin.balance;

        vm.prank(admin);
        gasTankModule.withdraw(EL_DIEGO, admin);

        assertEq(address(gasTankModule).balance, gasTankModuleETHBalanceBefore - 10);
        assertEq(admin.balance, adminETHBalanceBefore + 10);
    }

    function test_setAdminFeePercentage_onlyOwner() external {
        vm.prank(vegeta);
        vm.expectRevert("Ownable: caller is not the owner");
        gasTankModule.setAdminFeePercentage(1000);
    }

    function test_setAdminFeePercentage_invalidPercentage() external {
        vm.prank(admin);
        vm.expectRevert(GasTankModule.GasTankModule__setAdminFeePercentage_invalidPercentage.selector);
        gasTankModule.setAdminFeePercentage(100_001);
    }

    function test_execTransaction_onlyGelatoRelayERC2771() external {
        // build safe transaction for transferring USDC to some address
        bytes memory safePayload = getSafeUSDCTransferPayload(theSafe, kakarotoKey, vegeta, 10);

        // delegate signs fee approval
        bytes32 feeTxHash = gasTankModule.generateTransferHash(
            safeExternalGTProxy, DAI, 2, gasTankModule.nonces(safeExternalGTProxy, delegate)
        );
        (uint8 fee_v, bytes32 fee_r, bytes32 fee_s) = vm.sign(delegateKey, feeTxHash);
        bytes memory feeSignature = abi.encodePacked(fee_r, fee_s, fee_v);

        uint256 maxFee = 2;

        // build Gelato transaction
        bytes memory gasTankData = abi.encodeWithSelector(
            GasTankModule.execTransaction.selector, safeExternalGTProxy, safeProxy, safePayload, maxFee, feeSignature
        );
        bytes memory execData = abi.encodePacked(gasTankData, address(this), DAI, uint256(1), kakaroto);

        // execute directly
        vm.expectRevert("onlyGelatoRelayERC2771");
        Address.functionCall(address(gasTankModule), execData);
    }

    function test_execTransaction_from_owner_paying_fee_with_ERC20_should_work() external {
        uint256 safeUSDCBalanceBefore = ERC20(USDC).balanceOf(safeProxy);
        uint256 vegetaUSDCBalanceBefore = ERC20(USDC).balanceOf(vegeta);
        uint256 safeDAIBalanceBefore = ERC20(DAI).balanceOf(safeProxy);
        uint256 feeCollectorDAIBalanceBefore = ERC20(DAI).balanceOf(feeCollector);

        // build safe transaction for transferring USDC to some address
        bytes memory safePayload = getSafeUSDCTransferPayload(theSafe, kakarotoKey, vegeta, 10);

        // owner signs fee approval
        bytes32 feeTxHash =
            gasTankModule.generateTransferHash(safeProxy, DAI, 2, gasTankModule.nonces(safeProxy, kakaroto));
        (uint8 fee_v, bytes32 fee_r, bytes32 fee_s) = vm.sign(kakarotoKey, feeTxHash);
        bytes memory feeSignature = abi.encodePacked(fee_r, fee_s, fee_v);

        uint256 maxFee = 2;

        // build Gelato transaction
        bytes memory gasTankData = abi.encodeWithSelector(
            GasTankModule.execTransaction.selector, safeProxy, safeProxy, safePayload, maxFee, feeSignature
        );
        bytes memory gelatoData = getGelatoData(gasTankData, 1, DAI, kakaroto, kakarotoKey);

        // execute
        vm.prank(GELATO);
        Address.functionCall(address(gelatoRelay), gelatoData);

        assertEq(ERC20(USDC).balanceOf(safeProxy), safeUSDCBalanceBefore - 10);
        assertEq(ERC20(USDC).balanceOf(vegeta), vegetaUSDCBalanceBefore + 10);
        assertEq(ERC20(DAI).balanceOf(safeProxy), safeDAIBalanceBefore - 1);
        assertEq(ERC20(DAI).balanceOf(feeCollector), feeCollectorDAIBalanceBefore + 1);
    }

    function test_execTransaction_from_delegate_paying_fee_with_ERC20_should_work() external {
        uint256 safeUSDCBalanceBefore = ERC20(USDC).balanceOf(safeProxy);
        uint256 vegetaUSDCBalanceBefore = ERC20(USDC).balanceOf(vegeta);
        uint256 safeDAIBalanceBefore = ERC20(DAI).balanceOf(safeExternalGTProxy);
        uint256 feeCollectorDAIBalanceBefore = ERC20(DAI).balanceOf(feeCollector);

        // build safe transaction for transferring USDC to some address
        bytes memory safePayload = getSafeUSDCTransferPayload(theSafe, kakarotoKey, vegeta, 10);

        // delegate signs fee approval
        bytes32 feeTxHash = gasTankModule.generateTransferHash(
            safeExternalGTProxy, DAI, 2, gasTankModule.nonces(safeExternalGTProxy, delegate)
        );
        (uint8 fee_v, bytes32 fee_r, bytes32 fee_s) = vm.sign(delegateKey, feeTxHash);
        bytes memory feeSignature = abi.encodePacked(fee_r, fee_s, fee_v);

        uint256 maxFee = 2;

        // build Gelato transaction
        bytes memory gasTankData = abi.encodeWithSelector(
            GasTankModule.execTransaction.selector, safeExternalGTProxy, safeProxy, safePayload, maxFee, feeSignature
        );
        bytes memory gelatoData = getGelatoData(gasTankData, 1, DAI, delegate, delegateKey);

        // execute
        vm.prank(GELATO);
        Address.functionCall(address(gelatoRelay), gelatoData);

        assertEq(ERC20(USDC).balanceOf(safeProxy), safeUSDCBalanceBefore - 10);
        assertEq(ERC20(USDC).balanceOf(vegeta), vegetaUSDCBalanceBefore + 10);
        assertEq(ERC20(DAI).balanceOf(safeExternalGTProxy), safeDAIBalanceBefore - 1);
        assertEq(ERC20(DAI).balanceOf(feeCollector), feeCollectorDAIBalanceBefore + 1);
    }

    function test_execTransaction_from_owner_paying_fee_with_EL_DIEGO_should_work() external {
        uint256 safeUSDCBalanceBefore = ERC20(USDC).balanceOf(safeProxy);
        uint256 vegetaUSDCBalanceBefore = ERC20(USDC).balanceOf(vegeta);
        uint256 safeETHBalanceBefore = safeProxy.balance;
        uint256 feeCollectorETHBalanceBefore = feeCollector.balance;

        // build safe transaction for transferring USDC to some address
        bytes memory safePayload = getSafeUSDCTransferPayload(theSafe, kakarotoKey, vegeta, 10);

        // owner signs fee approval
        bytes32 feeTxHash =
            gasTankModule.generateTransferHash(safeProxy, EL_DIEGO, 2, gasTankModule.nonces(safeProxy, kakaroto));
        (uint8 fee_v, bytes32 fee_r, bytes32 fee_s) = vm.sign(kakarotoKey, feeTxHash);
        bytes memory feeSignature = abi.encodePacked(fee_r, fee_s, fee_v);

        uint256 maxFee = 2;

        // build Gelato transaction
        bytes memory gasTankData = abi.encodeWithSelector(
            GasTankModule.execTransaction.selector, safeProxy, safeProxy, safePayload, maxFee, feeSignature
        );
        bytes memory gelatoData = getGelatoData(gasTankData, 1, EL_DIEGO, kakaroto, kakarotoKey);

        // execute
        vm.prank(GELATO);
        Address.functionCall(address(gelatoRelay), gelatoData);

        assertEq(ERC20(USDC).balanceOf(safeProxy), safeUSDCBalanceBefore - 10);
        assertEq(ERC20(USDC).balanceOf(vegeta), vegetaUSDCBalanceBefore + 10);
        assertEq(safeProxy.balance, safeETHBalanceBefore - 1);
        assertEq(feeCollector.balance, feeCollectorETHBalanceBefore + 1);
    }

    function test_execTransaction_from_delegate_paying_fee_with_EL_DIEGO_should_work() external {
        uint256 safeUSDCBalanceBefore = ERC20(USDC).balanceOf(safeProxy);
        uint256 vegetaUSDCBalanceBefore = ERC20(USDC).balanceOf(vegeta);
        uint256 safeETHBalanceBefore = safeExternalGTProxy.balance;
        uint256 feeCollectorETHBalanceBefore = feeCollector.balance;

        // build safe transaction for transferring USDC to some address
        bytes memory safePayload = getSafeUSDCTransferPayload(theSafe, kakarotoKey, vegeta, 10);

        // delegate signs fee approval
        bytes32 feeTxHash = gasTankModule.generateTransferHash(
            safeExternalGTProxy, EL_DIEGO, 2, gasTankModule.nonces(safeExternalGTProxy, delegate)
        );
        (uint8 fee_v, bytes32 fee_r, bytes32 fee_s) = vm.sign(delegateKey, feeTxHash);
        bytes memory feeSignature = abi.encodePacked(fee_r, fee_s, fee_v);

        uint256 maxFee = 2;

        // build Gelato transaction
        bytes memory gasTankData = abi.encodeWithSelector(
            GasTankModule.execTransaction.selector, safeExternalGTProxy, safeProxy, safePayload, maxFee, feeSignature
        );
        bytes memory gelatoData = getGelatoData(gasTankData, 1, EL_DIEGO, delegate, delegateKey);

        // execute
        vm.prank(GELATO);
        Address.functionCall(address(gelatoRelay), gelatoData);

        assertEq(ERC20(USDC).balanceOf(safeProxy), safeUSDCBalanceBefore - 10);
        assertEq(ERC20(USDC).balanceOf(vegeta), vegetaUSDCBalanceBefore + 10);
        assertEq(safeExternalGTProxy.balance, safeETHBalanceBefore - 1);
        assertEq(feeCollector.balance, feeCollectorETHBalanceBefore + 1);
    }

    // addDelegate
    // GasTankModule__addDelegate_invalidDelegate
    function test_addDelegate_invalidDelegate() external {
        bytes memory payload = abi.encodeWithSelector(GasTankModule.addDelegate.selector, address(0));
        bytes32 txHash = getTransactionHash(theSafe, address(gasTankModule), payload);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(kakarotoKey, txHash);

        vm.prank(kakaroto);

        // Internally it reverts with GasTankModule__addDelegate_invalidDelegate.selector
        // You can use vvvv to prove I'm right :-P
        vm.expectRevert("GS013");
        theSafe.execTransaction(
            address(gasTankModule),
            0,
            payload,
            Enum.Operation.Call,
            0,
            0,
            0,
            address(0),
            payable(0),
            abi.encodePacked(r, s, v)
        );
    }
    // GasTankModule__addDelegate_alreadyDelegate

    function test_addDelegate_alreadyDelegate() external {
        addDelegate(delegate, theSafe, kakarotoKey);

        bytes memory payload = abi.encodeWithSelector(GasTankModule.addDelegate.selector, delegate);
        bytes32 txHash = getTransactionHash(theSafe, address(gasTankModule), payload);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(kakarotoKey, txHash);

        vm.prank(kakaroto);

        // Internally it reverts with GasTankModule__addDelegate_alreadyDelegate
        // You can use vvvv to prove I'm right :-P
        vm.expectRevert("GS013");
        theSafe.execTransaction(
            address(gasTankModule),
            0,
            payload,
            Enum.Operation.Call,
            0,
            0,
            0,
            address(0),
            payable(0),
            abi.encodePacked(r, s, v)
        );
    }

    // works
    // delegate
    // delegatedGasTank
    // tokens empty
    function test_addDelegate_should_work() external {
        addDelegate(delegate, theSafe, kakarotoKey);
        addDelegate(vegeta, theSafe, kakarotoKey);

        assertTrue(gasTankModule.isDelegate(safeProxy, delegate), "delegate should be a delegate");
        assertTrue(gasTankModule.isDelegate(safeProxy, vegeta), "vegeta should be a delegate");

        address[] memory delegates = gasTankModule.getDelegates(safeProxy);
        assertEq(delegates.length, 2, "should have 2 delegates");
        assertEq(delegates[0], delegate, "delegate should be the first delegate");
        assertEq(delegates[1], vegeta, "vegeta should be the second delegate");

        address[] memory delegatedSafes = gasTankModule.getDelegatedSafes(vegeta);
        assertEq(delegatedSafes.length, 1, "should have 1 delegated safe");
        assertEq(delegatedSafes[0], safeProxy, "sfe should be the first delegates safe");
    }

    // removeDelegate
    // GasTankModule__removeDelegate_invalidDelegate
    function test_removeDelegate_should_invalidDelegate() external {
        bytes memory payload = abi.encodeWithSelector(GasTankModule.removeDelegate.selector, address(0));
        bytes32 txHash = getTransactionHash(theSafe, address(gasTankModule), payload);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(kakarotoKey, txHash);

        vm.prank(kakaroto);

        // Internally it reverts with GasTankModule__removeDelegate_invalidDelegate
        // You can use vvvv to prove I'm right :-P
        vm.expectRevert("GS013");
        theSafe.execTransaction(
            address(gasTankModule),
            0,
            payload,
            Enum.Operation.Call,
            0,
            0,
            0,
            address(0),
            payable(0),
            abi.encodePacked(r, s, v)
        );
    }
    // works
    // delegate
    // delegatedGasTank
    // tokens empty

    function test_removeDelegate_should_work() external {
        addDelegate(vegeta, theSafe, kakarotoKey);

        assertTrue(gasTankModule.isDelegate(safeProxy, vegeta), "vegeta should be a delegate");

        address[] memory delegates = gasTankModule.getDelegates(safeProxy);
        assertEq(delegates.length, 1, "should have 1 delegates");
        assertEq(delegates[0], vegeta, "vegeta should be the first delegate");

        address[] memory delegatedSafes = gasTankModule.getDelegatedSafes(vegeta);
        assertEq(delegatedSafes.length, 1, "should have 1 delegated safe");
        assertEq(delegatedSafes[0], safeProxy, "sfe should be the first delegates safe");

        removeDelegate(vegeta, theSafe, kakarotoKey);
        assertFalse(gasTankModule.isDelegate(safeProxy, vegeta), "vegeta should not be a delegate");

        delegates = gasTankModule.getDelegates(safeProxy);
        assertEq(delegates.length, 0, "should have 0 delegates");

        delegatedSafes = gasTankModule.getDelegatedSafes(vegeta);
        assertEq(delegatedSafes.length, 0, "should have 0 delegated safe");
    }

    // addTokenAllowance
    // GasTankModule__setTokenAllowance_invalidDelegate
    function test_addTokenAllowance_should_invalidDelegate() external {
        bytes memory payload = abi.encodeWithSelector(GasTankModule.addTokenAllowance.selector, address(0), USDC);
        bytes32 txHash = getTransactionHash(theSafe, address(gasTankModule), payload);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(kakarotoKey, txHash);

        vm.prank(kakaroto);

        // Internally it reverts with GasTankModule__setTokenAllowance_invalidDelegate
        // You can use vvvv to prove I'm right :-P
        vm.expectRevert("GS013");
        theSafe.execTransaction(
            address(gasTankModule),
            0,
            payload,
            Enum.Operation.Call,
            0,
            0,
            0,
            address(0),
            payable(0),
            abi.encodePacked(r, s, v)
        );
    }
    // GasTankModule__setTokenAllowance_notDelegate

    function test_addTokenAllowance_should_notDelegate() external {
        bytes memory payload = abi.encodeWithSelector(GasTankModule.addTokenAllowance.selector, vegeta, USDC);
        bytes32 txHash = getTransactionHash(theSafe, address(gasTankModule), payload);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(kakarotoKey, txHash);

        vm.prank(kakaroto);

        // Internally it reverts with GasTankModule__setTokenAllowance_notDelegate
        // You can use vvvv to prove I'm right :-P
        vm.expectRevert("GS013");
        theSafe.execTransaction(
            address(gasTankModule),
            0,
            payload,
            Enum.Operation.Call,
            0,
            0,
            0,
            address(0),
            payable(0),
            abi.encodePacked(r, s, v)
        );
    }
    // works add new token

    function test_addTokenAllowance_should_work() external {
        addDelegate(vegeta, theSafe, kakarotoKey);
        address[] memory tokens = gasTankModule.getTokens(safeProxy, vegeta);
        assertEq(tokens.length, 0, "should have 0 tokens allowed");

        addTokenAllowance(vegeta, USDC, theSafe, kakarotoKey);
        addTokenAllowance(vegeta, DAI, theSafe, kakarotoKey);

        tokens = gasTankModule.getTokens(safeProxy, vegeta);

        assertEq(tokens.length, 2, "should have 2 tokens allowed");
        assertEq(tokens[0], USDC, "USDC should be allowed");
        assertEq(tokens[1], DAI, "DAI should be allowed");
    }
    // works with repeated toke

    function test_addTokenAllowance_should_work_adding_the_same_token() external {
        addDelegate(vegeta, theSafe, kakarotoKey);
        address[] memory tokens = gasTankModule.getTokens(safeProxy, vegeta);
        assertEq(tokens.length, 0, "should have 0 tokens allowed");

        addTokenAllowance(vegeta, USDC, theSafe, kakarotoKey);
        addTokenAllowance(vegeta, DAI, theSafe, kakarotoKey);

        tokens = gasTankModule.getTokens(safeProxy, vegeta);

        assertEq(tokens.length, 2, "should have 2 tokens allowed");
        assertEq(tokens[0], USDC, "USDC should be allowed");
        assertEq(tokens[1], DAI, "DAI should be allowed");

        addTokenAllowance(vegeta, USDC, theSafe, kakarotoKey);

        tokens = gasTankModule.getTokens(safeProxy, vegeta);

        assertEq(tokens.length, 2, "should have 2 tokens allowed");
        assertEq(tokens[0], USDC, "USDC should be allowed");
        assertEq(tokens[1], DAI, "DAI should be allowed");
    }

    // removeTokenAllowance
    // GasTankModule__removeTokenAllowance_invalidDelegate
    function test_removeTokenAllowance_should_invalidDelegate() external {
        bytes memory payload = abi.encodeWithSelector(GasTankModule.removeTokenAllowance.selector, address(0), USDC);
        bytes32 txHash = getTransactionHash(theSafe, address(gasTankModule), payload);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(kakarotoKey, txHash);

        vm.prank(kakaroto);

        // Internally it reverts with GasTankModule__removeTokenAllowance_invalidDelegate
        // You can use vvvv to prove I'm right :-P
        vm.expectRevert("GS013");
        theSafe.execTransaction(
            address(gasTankModule),
            0,
            payload,
            Enum.Operation.Call,
            0,
            0,
            0,
            address(0),
            payable(0),
            abi.encodePacked(r, s, v)
        );
    }
    // GasTankModule__removeTokenAllowance_notDelegate

    function test_removeTokenAllowance_should_notDelegate() external {
        bytes memory payload = abi.encodeWithSelector(GasTankModule.removeTokenAllowance.selector, vegeta, USDC);
        bytes32 txHash = getTransactionHash(theSafe, address(gasTankModule), payload);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(kakarotoKey, txHash);

        vm.prank(kakaroto);

        // Internally it reverts with GasTankModule__removeTokenAllowance_notDelegate
        // You can use vvvv to prove I'm right :-P
        vm.expectRevert("GS013");
        theSafe.execTransaction(
            address(gasTankModule),
            0,
            payload,
            Enum.Operation.Call,
            0,
            0,
            0,
            address(0),
            payable(0),
            abi.encodePacked(r, s, v)
        );
    }
    // works remove new token

    function test_removeTokenAllowance_should_work() external {
        addDelegate(vegeta, theSafe, kakarotoKey);
        address[] memory tokens = gasTankModule.getTokens(safeProxy, vegeta);
        assertEq(tokens.length, 0, "should have 0 tokens allowed");

        addTokenAllowance(vegeta, USDC, theSafe, kakarotoKey);
        addTokenAllowance(vegeta, DAI, theSafe, kakarotoKey);

        tokens = gasTankModule.getTokens(safeProxy, vegeta);

        assertEq(tokens.length, 2, "should have 0 tokens allowed");
        assertEq(tokens[0], USDC, "USDC should be allowed");
        assertEq(tokens[1], DAI, "DAI should be allowed");

        removeTokenAllowance(vegeta, USDC, theSafe, kakarotoKey);

        tokens = gasTankModule.getTokens(safeProxy, vegeta);

        assertEq(tokens.length, 1, "should have 1 tokens allowed");
        assertEq(tokens[0], DAI, "DAI should be allowed");
    }
    // works with not added token

    function test_removeTokenAllowance_should_work_removing_token_not_added() external {
        addDelegate(vegeta, theSafe, kakarotoKey);
        address[] memory tokens = gasTankModule.getTokens(safeProxy, vegeta);
        assertEq(tokens.length, 0, "should have 0 tokens allowed");

        addTokenAllowance(vegeta, DAI, theSafe, kakarotoKey);

        tokens = gasTankModule.getTokens(safeProxy, vegeta);

        assertEq(tokens.length, 1, "should have 1 tokens allowed");
        assertEq(tokens[0], DAI, "DAI should be allowed");

        removeTokenAllowance(vegeta, USDC, theSafe, kakarotoKey);

        tokens = gasTankModule.getTokens(safeProxy, vegeta);

        assertEq(tokens.length, 1, "should have 1 tokens allowed");
        assertEq(tokens[0], DAI, "DAI should be allowed");
    }

    // getDelegates
    // getDelegatedSafes
    // isDelegates
    // getTokens

    // _payFee
    // GasTankModule__getFees_invalidSigner
    // feeToken not the same
    function test_payFee_invalidSigner_when_signed_feeToken_not_the_same() external {
        // build safe transaction for transferring USDC to some address
        bytes memory safePayload = getSafeUSDCTransferPayload(theSafe, kakarotoKey, vegeta, 10);

        // owner signs fee approval
        bytes32 feeTxHash =
            gasTankModule.generateTransferHash(safeProxy, DAI, 2, gasTankModule.nonces(safeProxy, kakaroto));
        (uint8 fee_v, bytes32 fee_r, bytes32 fee_s) = vm.sign(kakarotoKey, feeTxHash);
        bytes memory feeSignature = abi.encodePacked(fee_r, fee_s, fee_v);

        uint256 maxFee = 2;

        // build Gelato transaction
        bytes memory gasTankData = abi.encodeWithSelector(
            GasTankModule.execTransaction.selector, safeProxy, safeProxy, safePayload, maxFee, feeSignature
        );
        bytes memory gelatoData = getGelatoData(gasTankData, 1, USDC, kakaroto, kakarotoKey);

        // execute
        vm.prank(GELATO);
        vm.expectRevert("GelatoRelayERC2771.callWithSyncFeeERC2771:NoErrorSelector"); // Gelato is not creating error
            // message from custom errors
        Address.functionCall(address(gelatoRelay), gelatoData);
    }
    // invalidated signature by nonce

    function test_payFee_invalidSigner_on_replay() external {
        uint256 safeUSDCBalanceBefore = ERC20(USDC).balanceOf(safeProxy);
        uint256 vegetaUSDCBalanceBefore = ERC20(USDC).balanceOf(vegeta);
        uint256 safeDAIBalanceBefore = ERC20(DAI).balanceOf(safeProxy);
        uint256 feeCollectorDAIBalanceBefore = ERC20(DAI).balanceOf(feeCollector);

        // build safe transaction for transferring USDC to some address
        bytes memory safePayload = getSafeUSDCTransferPayload(theSafe, kakarotoKey, vegeta, 10);

        // owner signs fee approval
        bytes32 feeTxHash =
            gasTankModule.generateTransferHash(safeProxy, DAI, 2, gasTankModule.nonces(safeProxy, kakaroto));
        (uint8 fee_v, bytes32 fee_r, bytes32 fee_s) = vm.sign(kakarotoKey, feeTxHash);
        bytes memory feeSignature = abi.encodePacked(fee_r, fee_s, fee_v);

        uint256 maxFee = 2;

        // build Gelato transaction
        bytes memory gasTankData = abi.encodeWithSelector(
            GasTankModule.execTransaction.selector, safeProxy, safeProxy, safePayload, maxFee, feeSignature
        );
        bytes memory gelatoData = getGelatoData(gasTankData, 1, DAI, kakaroto, kakarotoKey);

        // execute
        vm.prank(GELATO);
        Address.functionCall(address(gelatoRelay), gelatoData);

        assertEq(ERC20(USDC).balanceOf(safeProxy), safeUSDCBalanceBefore - 10);
        assertEq(ERC20(USDC).balanceOf(vegeta), vegetaUSDCBalanceBefore + 10);
        assertEq(ERC20(DAI).balanceOf(safeProxy), safeDAIBalanceBefore - 1);
        assertEq(ERC20(DAI).balanceOf(feeCollector), feeCollectorDAIBalanceBefore + 1);

        // build new Gelato transaction with same fee signature
        gasTankData = abi.encodeWithSelector(
            GasTankModule.execTransaction.selector, safeProxy, safeProxy, safePayload, maxFee, feeSignature
        );
        gelatoData = getGelatoData(gasTankData, 1, DAI, kakaroto, kakarotoKey);

        // replay
        vm.prank(GELATO);
        vm.expectRevert("GelatoRelayERC2771.callWithSyncFeeERC2771:NoErrorSelector"); // Gelato is not creating error
            // message from custom errors
        Address.functionCall(address(gelatoRelay), gelatoData);
    }

    //GasTankModule__getFee_notOwnerOrDelegate
    // not owner
    function test_payFee_notOwnerOrDelegate_when_not_owner() external {
        // build safe transaction for transferring USDC to some address
        bytes memory safePayload = getSafeUSDCTransferPayload(theSafe, kakarotoKey, vegeta, 10);

        // owner signs fee approval
        bytes32 feeTxHash =
            gasTankModule.generateTransferHash(safeProxy, DAI, 2, gasTankModule.nonces(safeProxy, vegeta));
        (uint8 fee_v, bytes32 fee_r, bytes32 fee_s) = vm.sign(vegetaKey, feeTxHash);
        bytes memory feeSignature = abi.encodePacked(fee_r, fee_s, fee_v);

        uint256 maxFee = 2;

        // build Gelato transaction
        bytes memory gasTankData = abi.encodeWithSelector(
            GasTankModule.execTransaction.selector, safeProxy, safeProxy, safePayload, maxFee, feeSignature
        );
        bytes memory gelatoData = getGelatoData(gasTankData, 1, DAI, vegeta, vegetaKey);

        // execute
        vm.prank(GELATO);
        vm.expectRevert("GelatoRelayERC2771.callWithSyncFeeERC2771:NoErrorSelector"); // Gelato is not creating error
            // message from custom errors
        Address.functionCall(address(gelatoRelay), gelatoData);
    }
    // not delegate

    function test_payFee_notOwnerOrDelegate_when_not_delegate() external {
        // build safe transaction for transferring USDC to some address
        bytes memory safePayload = getSafeUSDCTransferPayload(theSafe, kakarotoKey, vegeta, 10);

        // delegate signs fee approval
        bytes32 feeTxHash = gasTankModule.generateTransferHash(
            safeExternalGTProxy, DAI, 2, gasTankModule.nonces(safeExternalGTProxy, kakaroto)
        );
        (uint8 fee_v, bytes32 fee_r, bytes32 fee_s) = vm.sign(kakarotoKey, feeTxHash);
        bytes memory feeSignature = abi.encodePacked(fee_r, fee_s, fee_v);

        uint256 maxFee = 2;

        // build Gelato transaction
        bytes memory gasTankData = abi.encodeWithSelector(
            GasTankModule.execTransaction.selector, safeExternalGTProxy, safeProxy, safePayload, maxFee, feeSignature
        );
        bytes memory gelatoData = getGelatoData(gasTankData, 1, DAI, kakaroto, kakarotoKey);

        // execute
        vm.prank(GELATO);
        vm.expectRevert("GelatoRelayERC2771.callWithSyncFeeERC2771:NoErrorSelector"); // Gelato is not creating error
            // message from custom errors
        Address.functionCall(address(gelatoRelay), gelatoData);
    }

    // no admin fee
    // totalFee > max fee GasTankModule__getFee_maxFee
    function test_payFee_maxFee_with_no_admin_fee() external {
        // build safe transaction for transferring USDC to some address
        bytes memory safePayload = getSafeUSDCTransferPayload(theSafe, kakarotoKey, vegeta, 10);

        // owner signs fee approval
        bytes32 feeTxHash =
            gasTankModule.generateTransferHash(safeProxy, DAI, 2, gasTankModule.nonces(safeProxy, kakaroto));
        (uint8 fee_v, bytes32 fee_r, bytes32 fee_s) = vm.sign(kakarotoKey, feeTxHash);
        bytes memory feeSignature = abi.encodePacked(fee_r, fee_s, fee_v);

        uint256 maxFee = 2;

        // build Gelato transaction
        bytes memory gasTankData = abi.encodeWithSelector(
            GasTankModule.execTransaction.selector, safeProxy, safeProxy, safePayload, maxFee, feeSignature
        );
        bytes memory gelatoData = getGelatoData(gasTankData, 3, DAI, kakaroto, kakarotoKey);

        // execute
        vm.prank(GELATO);
        vm.expectRevert("GelatoRelayERC2771.callWithSyncFeeERC2771:NoErrorSelector"); // Gelato is not creating error
            // message from custom errors
        Address.functionCall(address(gelatoRelay), gelatoData);
    }

    // admin fee
    function test_payFee_maxFee_with_admin_fee() external {
        vm.prank(admin);
        gasTankModule.setAdminFeePercentage(100_000); // 100%

        vm.prank(admin);

        bytes memory safePayload = getSafeUSDCTransferPayload(theSafe, kakarotoKey, vegeta, 10);

        // owner signs fee approval
        bytes32 feeTxHash =
            gasTankModule.generateTransferHash(safeProxy, DAI, 2, gasTankModule.nonces(safeProxy, kakaroto));
        (uint8 fee_v, bytes32 fee_r, bytes32 fee_s) = vm.sign(kakarotoKey, feeTxHash);
        bytes memory feeSignature = abi.encodePacked(fee_r, fee_s, fee_v);

        uint256 maxFee = 2;

        // build Gelato transaction
        bytes memory gasTankData = abi.encodeWithSelector(
            GasTankModule.execTransaction.selector, safeProxy, safeProxy, safePayload, maxFee, feeSignature
        );
        bytes memory gelatoData = getGelatoData(gasTankData, 2, DAI, kakaroto, kakarotoKey);

        // execute
        vm.prank(GELATO);
        vm.expectRevert("GelatoRelayERC2771.callWithSyncFeeERC2771:NoErrorSelector"); // Gelato is not creating error
            // message from custom errors
        Address.functionCall(address(gelatoRelay), gelatoData);
    }
    // no treasury set

    function test_payFee_should_not_charge_admin_fee_when_fee_is_0() external {
        vm.prank(admin);
        gasTankModule.setAdminFeePercentage(0); // 0%

        uint256 safeUSDCBalanceBefore = ERC20(USDC).balanceOf(safeProxy);
        uint256 vegetaUSDCBalanceBefore = ERC20(USDC).balanceOf(vegeta);
        uint256 safeDAIBalanceBefore = ERC20(DAI).balanceOf(safeProxy);
        uint256 feeCollectorDAIBalanceBefore = ERC20(DAI).balanceOf(feeCollector);

        // build safe transaction for transferring USDC to some address
        bytes memory safePayload = getSafeUSDCTransferPayload(theSafe, kakarotoKey, vegeta, 10);

        // owner signs fee approval
        bytes32 feeTxHash =
            gasTankModule.generateTransferHash(safeProxy, DAI, 2, gasTankModule.nonces(safeProxy, kakaroto));
        (uint8 fee_v, bytes32 fee_r, bytes32 fee_s) = vm.sign(kakarotoKey, feeTxHash);
        bytes memory feeSignature = abi.encodePacked(fee_r, fee_s, fee_v);

        uint256 maxFee = 2;

        // build Gelato transaction
        bytes memory gasTankData = abi.encodeWithSelector(
            GasTankModule.execTransaction.selector, safeProxy, safeProxy, safePayload, maxFee, feeSignature
        );
        bytes memory gelatoData = getGelatoData(gasTankData, 1, DAI, kakaroto, kakarotoKey);

        // execute
        vm.prank(GELATO);
        Address.functionCall(address(gelatoRelay), gelatoData);

        assertEq(ERC20(USDC).balanceOf(safeProxy), safeUSDCBalanceBefore - 10);
        assertEq(ERC20(USDC).balanceOf(vegeta), vegetaUSDCBalanceBefore + 10);
        assertEq(ERC20(DAI).balanceOf(safeProxy), safeDAIBalanceBefore - 1);
        assertEq(ERC20(DAI).balanceOf(feeCollector), feeCollectorDAIBalanceBefore + 1);
    }
    // works

    function test_payFee_should_keep_ERC20_admin_fee() external {
        vm.prank(admin);
        gasTankModule.setAdminFeePercentage(100_000); // 1000%

        uint256 safeUSDCBalanceBefore = ERC20(USDC).balanceOf(safeProxy);
        uint256 vegetaUSDCBalanceBefore = ERC20(USDC).balanceOf(vegeta);
        uint256 safeDAIBalanceBefore = ERC20(DAI).balanceOf(safeProxy);
        uint256 feeCollectorDAIBalanceBefore = ERC20(DAI).balanceOf(feeCollector);
        uint256 gasTankModuleDAIBalanceBefore = ERC20(DAI).balanceOf(address(gasTankModule));

        // owner signs fee approval
        bytes32 feeTxHash =
            gasTankModule.generateTransferHash(safeProxy, DAI, 2, gasTankModule.nonces(safeProxy, kakaroto));
        (uint8 fee_v, bytes32 fee_r, bytes32 fee_s) = vm.sign(kakarotoKey, feeTxHash);
        bytes memory feeSignature = abi.encodePacked(fee_r, fee_s, fee_v);

        uint256 maxFee = 2;

        // build Gelato transaction
        bytes memory gasTankData = abi.encodeWithSelector(
            GasTankModule.execTransaction.selector,
            safeProxy,
            safeProxy,
            getSafeUSDCTransferPayload(theSafe, kakarotoKey, vegeta, 10),
            maxFee,
            feeSignature
        );
        bytes memory gelatoData = getGelatoData(gasTankData, 1, DAI, kakaroto, kakarotoKey);

        // execute
        vm.prank(GELATO);
        Address.functionCall(address(gelatoRelay), gelatoData);

        assertEq(ERC20(USDC).balanceOf(safeProxy), safeUSDCBalanceBefore - 10);
        assertEq(ERC20(USDC).balanceOf(vegeta), vegetaUSDCBalanceBefore + 10);
        assertEq(ERC20(DAI).balanceOf(safeProxy), safeDAIBalanceBefore - 2);
        assertEq(ERC20(DAI).balanceOf(feeCollector), feeCollectorDAIBalanceBefore + 1);
        assertEq(ERC20(DAI).balanceOf(address(gasTankModule)), gasTankModuleDAIBalanceBefore + 1);
    }

    function test_payFee_should_keep_ETH_admin_fee() external {
        vm.prank(admin);
        gasTankModule.setAdminFeePercentage(100_000); // 1000%

        uint256 safeUSDCBalanceBefore = ERC20(USDC).balanceOf(safeProxy);
        uint256 vegetaUSDCBalanceBefore = ERC20(USDC).balanceOf(vegeta);
        uint256 safeETHBalanceBefore = safeProxy.balance;
        uint256 feeCollectorETHBalanceBefore = feeCollector.balance;
        uint256 gasTankModuleETHBalanceBefore = address(gasTankModule).balance;

        // owner signs fee approval
        bytes32 feeTxHash =
            gasTankModule.generateTransferHash(safeProxy, EL_DIEGO, 2, gasTankModule.nonces(safeProxy, kakaroto));
        (uint8 fee_v, bytes32 fee_r, bytes32 fee_s) = vm.sign(kakarotoKey, feeTxHash);
        bytes memory feeSignature = abi.encodePacked(fee_r, fee_s, fee_v);

        uint256 maxFee = 2;

        // build Gelato transaction
        bytes memory gasTankData = abi.encodeWithSelector(
            GasTankModule.execTransaction.selector,
            safeProxy,
            safeProxy,
            getSafeUSDCTransferPayload(theSafe, kakarotoKey, vegeta, 10),
            maxFee,
            feeSignature
        );
        bytes memory gelatoData = getGelatoData(gasTankData, 1, EL_DIEGO, kakaroto, kakarotoKey);

        // execute
        vm.prank(GELATO);
        Address.functionCall(address(gelatoRelay), gelatoData);

        assertEq(ERC20(USDC).balanceOf(safeProxy), safeUSDCBalanceBefore - 10);
        assertEq(ERC20(USDC).balanceOf(vegeta), vegetaUSDCBalanceBefore + 10);
        assertEq(safeProxy.balance, safeETHBalanceBefore - 2);
        assertEq(feeCollector.balance, feeCollectorETHBalanceBefore + 1);
        assertEq(address(gasTankModule).balance, gasTankModuleETHBalanceBefore + 1);
    }

    /////////////////////////////
    ////////// HELPERS //////////
    /////////////////////////////

    function getSafeUSDCTransferPayload(
        Safe safe,
        uint256 signerKey,
        address receiver,
        uint256 amount
    )
        internal
        view
        returns (bytes memory)
    {
        // owner sings safe transaction
        bytes memory erc20TransferPayload = abi.encodeWithSelector(ERC20.transfer.selector, receiver, amount);
        bytes32 txHash = getTransactionHash(safe, USDC, erc20TransferPayload);
        (uint8 v, bytes32 r, bytes32 _s) = vm.sign(signerKey, txHash);

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

    function addDelegate(address _delegate, Safe safe, uint256 signerKey) internal {
        bytes memory payload = abi.encodeWithSelector(GasTankModule.addDelegate.selector, _delegate);
        execTransaction(safe, address(gasTankModule), payload, signerKey);
    }

    function removeDelegate(address _delegate, Safe safe, uint256 signerKey) internal {
        bytes memory payload = abi.encodeWithSelector(GasTankModule.removeDelegate.selector, _delegate);
        execTransaction(safe, address(gasTankModule), payload, signerKey);
    }

    function addTokenAllowance(address _delegate, address _token, Safe safe, uint256 signerKey) internal {
        bytes memory payload = abi.encodeWithSelector(GasTankModule.addTokenAllowance.selector, _delegate, _token);
        execTransaction(safe, address(gasTankModule), payload, signerKey);
    }

    function removeTokenAllowance(address _delegate, address _token, Safe safe, uint256 signerKey) internal {
        bytes memory payload = abi.encodeWithSelector(GasTankModule.removeTokenAllowance.selector, _delegate, _token);
        execTransaction(safe, address(gasTankModule), payload, signerKey);
    }

    function setDelegateAndTokens(Safe safe, uint256 signerKey, address eldelegate, address[] memory tokens) internal {
        bytes memory payload = abi.encodeWithSelector(GasTankModule.addDelegate.selector, eldelegate);
        execTransaction(safe, address(gasTankModule), payload, signerKey);

        for (uint256 i = 0; i < tokens.length; i++) {
            addTokenAllowance(eldelegate, tokens[i], safe, signerKey);
        }
    }

    function getGelatoData(
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
            block.chainid, address(gasTankModule), gtData, sender, gelatoRelay.userNonce(sender), 0
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
