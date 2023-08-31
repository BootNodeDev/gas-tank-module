// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.19;

import { Enum } from "safe-contracts/contracts/common/Enum.sol";
import { SignatureDecoder } from "safe-contracts/contracts/common/SignatureDecoder.sol";
import { Safe } from "safe-contracts/contracts/Safe.sol";
import { SafeStorage } from "safe-contracts/contracts/libraries/SafeStorage.sol";

import { GelatoRelayContextERC2771 } from "@gelatonetwork/relay-context/contracts/GelatoRelayContextERC2771.sol";

import { Address } from "@openzeppelin/contracts/utils/Address.sol";
import { EnumerableSet } from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

contract GasTank is SafeStorage, SignatureDecoder, GelatoRelayContextERC2771 {
    using EnumerableSet for EnumerableSet.AddressSet;

    address public immutable myAddress;

    address internal constant SENTINEL_MODULES = address(0x1);

    // keccak256(
    //     "EIP712Domain(uint256 chainId,address verifyingContract)"
    // );
    bytes32 public constant DOMAIN_SEPARATOR_TYPEHASH =
        0x47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218;

    // keccak256(
    //     "AllowanceTransfer(address safe,address feeToken,uint96 relayFee,uint16 nonce)"
    // );
    bytes32 public constant ALLOWANCE_TRANSFER_TYPEHASH =
        0xe6c1e62ea9344786169d5b9c56c470d5e3500a1f1813b5e8578dfffff4f4a8ed;

    mapping(address gasTank => mapping(address signer => uint16 nonce)) public nonces;

    mapping(address gasTank => EnumerableSet.AddressSet) internal delegates;
    mapping(address delegate => EnumerableSet.AddressSet) internal delegatedGasTanks;

    // index 0 is used for no when delegate is not a real delegate
    mapping(address gasTank => mapping(address delegate => mapping(uint16 index => EnumerableSet.AddressSet))) internal tokens;
    mapping(address gasTank => mapping(address delegate => uint16 index)) internal delegatesCurrentIndex;

    event AddDelegate(address indexed safe, address delegate);
    event RemoveDelegate(address indexed safe, address delegate);
    event AddTokenAllowance(address indexed safe, address indexed delegate, address indexed token);
    event RemoveTokenAllowance(address indexed safe, address indexed delegate, address indexed token);
    event GetFeesFromOwner(address indexed safe, address indexed owner, address token, uint256 relayerFee);
    event GetFeesFromDelegate(address indexed safe, address indexed delegate, address token, uint256 relayerFee);

    error GasTank__getFee_notOwnerOrDelegate();
    error GasTank__getFee_maxFee();
    error GasTank__getFees_invalidSigner();
    error GasTank__addDelegate_invalidDelegate();
    error GasTank__removeDelegate_invalidDelegate();
    error GasTank__addDelegate_alreadyDelegate();
    error GasTank__setTokenAllowance_invalidDelegate();
    error GasTank__setTokenAllowance_notDelegate();
    error GasTank__removeTokenAllowance_invalidDelegate();
    error GasTank__removeTokenAllowance_notDelegate();
    error GasTank__getFeesFromDelegate_invalidDelegate();
    error GasTank__getFeesFromDelegate_tokenNotAllowed();
    error GasTank__getFeesFromDelegate_invalidSigner();
    error GasTank__getFeesFromDelegate_notDelegate();
    error GasTank__recoverSignature_invalidSignatureLength();
    error GasTank__recoverSignature_contractSignatureNotSupported();
    error GasTank__recoverSignature_invalidSigner();
    error GasTank__transfer_ETH();
    error GasTank__transfer_ERC20();

    constructor() {
        myAddress = address(this);
    }

    function enableMyself() public {
        require(myAddress != address(this), "You need to DELEGATECALL, sir");

        // Module cannot be added twice.
        require(modules[myAddress] == address(0), "GS102");
        modules[myAddress] = modules[SENTINEL_MODULES];
        modules[SENTINEL_MODULES] = myAddress;
    }

    function execTransaction(
        address _gasTank,
        address _safe,
        bytes memory _txData,
        uint256 _maxFee,
        bytes memory _feeSignature
    ) public onlyGelatoRelayERC2771 returns (bool success) {
        _payFee(_gasTank, _maxFee, _feeSignature);

        bool returnData = abi.decode(Address.functionCall(_safe, _txData), (bool));

        return returnData;
    }

    function _payFee(address _gasTank, uint256 _maxFee, bytes memory _feeSignature) internal {
        address feeToken = _getFeeToken();
        uint256 relayerFee = _getFee();

        address sender = _getMsgSender();
        uint16 signerNonce = nonces[_gasTank][sender];
        bytes memory transferHashData =
            generateTransferHashData(address(_gasTank), feeToken, _maxFee, signerNonce);

        // Update nonce
        nonces[_gasTank][sender] += 1;

        // Check signature
        address signer = recoverSignature(_feeSignature, transferHashData);
        if (sender != signer) revert GasTank__getFees_invalidSigner();

        // check signer is owner or delegate
        if (!isOwnerOrDelegate(_gasTank, signer, feeToken)) revert GasTank__getFee_notOwnerOrDelegate();
        if (relayerFee > _maxFee) revert GasTank__getFee_maxFee();

        // Transfer fee from safe to this contract
        transfer(Safe(payable(_gasTank)), feeToken, payable(address(this)), relayerFee);

        // Payment to Gelato
        _transferRelayFee();
    }

    function isOwnerOrDelegate(address _gasTank, address _signer, address _feeToken) internal view returns(bool) {
        if (Safe(payable(_gasTank)).isOwner(_signer)) {
            return true;
        }

        uint16 currentIndex = delegatesCurrentIndex[_gasTank][_signer];
        if (delegates[_gasTank].contains(_signer) && tokens[_gasTank][_signer][currentIndex].contains(_feeToken)) {
            return true;
        }

        return false;
    }

    /// @dev Allows to add a delegate.
    /// @param delegate Delegate that should be added.
    function addDelegate(address delegate) public {
        if (delegate == address(0)) revert GasTank__addDelegate_invalidDelegate();
        if (delegates[msg.sender].contains(delegate)) revert GasTank__addDelegate_alreadyDelegate();

        delegates[msg.sender].add(delegate);
        delegatedGasTanks[delegate].add(msg.sender);
        delegatesCurrentIndex[msg.sender][delegate] += 1;

        emit AddDelegate(msg.sender, delegate);
    }

    /// @dev Allows to remove a delegate.
    /// @param delegate Delegate that should be removed.
    function removeDelegate(address delegate) public {
        if (delegate == address(0)) revert GasTank__removeDelegate_invalidDelegate();

        delegates[msg.sender].remove(delegate);
        delegatedGasTanks[delegate].remove(msg.sender);

        emit RemoveDelegate(msg.sender, delegate);
    }

    function getDelegates(address safe) public view returns (address[] memory) {
        return delegates[safe].values();
    }

    function getDelegatedSafes(address delegate) public view returns (address[] memory) {
        return delegatedGasTanks[delegate].values();
    }

    function isDelegates(address safe, address delegate) public view returns (bool) {
        return delegates[safe].contains(delegate);
    }

    /// @dev Allows to update the allowance for a specified token. This can only be done via a Safe transaction.
    /// @param delegate Delegate whose allowance should be updated.
    /// @param token Token contract address.
    function addTokenAllowance(address delegate,address token) public {
        if (delegate == address(0)) revert GasTank__setTokenAllowance_invalidDelegate();
        if (!delegates[msg.sender].contains(delegate)) revert GasTank__setTokenAllowance_notDelegate();

        uint16 currentIndex = delegatesCurrentIndex[msg.sender][delegate];

        tokens[msg.sender][delegate][currentIndex].add(token);

        emit AddTokenAllowance(msg.sender, delegate, token);
    }

    function removeTokenAllowance(address delegate,address token) public {
        if (delegate == address(0)) revert GasTank__removeTokenAllowance_invalidDelegate();
        if (!delegates[msg.sender].contains(delegate)) revert GasTank__removeTokenAllowance_notDelegate();

        uint16 currentIndex = delegatesCurrentIndex[msg.sender][delegate];

        tokens[msg.sender][delegate][currentIndex].remove(token);

        emit RemoveTokenAllowance(msg.sender, delegate, token);
    }

    function getTokens(address safe, address delegate) public view returns (address[] memory) {
        uint16 currentIndex = delegates[msg.sender].contains(delegate) ? delegatesCurrentIndex[safe][delegate] : 0;

        return tokens[safe][delegate][currentIndex].values();
    }


    /// @dev Returns the chain id used by this contract.
    function getChainId() public view returns (uint256) {
        return block.chainid;
    }

    /// @dev Generates the data for the transfer hash (required for signing)
    function generateTransferHashData(
        address safe,
        address token,
        uint256 amount,
        uint16 nonce
    )
        private
        view
        returns (bytes memory)
    {
        uint256 chainId = getChainId();
        bytes32 domainSeparator = keccak256(abi.encode(DOMAIN_SEPARATOR_TYPEHASH, chainId, this));
        bytes32 transferHash =
            keccak256(abi.encode(ALLOWANCE_TRANSFER_TYPEHASH, safe, token, address(this), amount, nonce));
        return abi.encodePacked(bytes1(0x19), bytes1(0x01), domainSeparator, transferHash);
    }

    /// @dev Generates the transfer hash that should be signed to authorize a transfer
    function generateTransferHash(
        address safe,
        address token,
        uint96 amount,
        uint16 nonce
    ) public view returns (bytes32) {
        return keccak256(generateTransferHashData(safe, token, amount, nonce));
    }

    // We use the same format as used for the Safe contract, except that we only support exactly 1 signature and no
    // contract signatures.
    function recoverSignature(
        bytes memory signature,
        bytes memory transferHashData
    ) private view returns (address signer) {
        // If there is no signature data msg.sender should be used
        if (signature.length == 0) return msg.sender;
        // Check that the provided signature data is as long as 1 encoded ecsda signature
        if (signature.length != 65) revert GasTank__recoverSignature_invalidSignatureLength();
        uint8 v;
        bytes32 r;
        bytes32 s;
        (v, r, s) = signatureSplit(signature, 0);
        // If v is 0 then it is a contract signature
        if (v == 0) {
            revert GasTank__recoverSignature_contractSignatureNotSupported();
        } else if (v == 1) {
            // If v is 1 we also use msg.sender, this is so that we are compatible to the GnosisSafe signature scheme
            signer = msg.sender;
        } else if (v > 30) {
            // To support eth_sign and similar we adjust v and hash the transferHashData with the Ethereum message
            // prefix before applying ecrecover
            signer = ecrecover(
                keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(transferHashData))),
                v - 4,
                r,
                s
            );
        } else {
            // Use ecrecover with the messageHash for EOA signatures
            signer = ecrecover(keccak256(transferHashData), v, r, s);
        }
        // 0 for the recovered signer indicates that an error happened.
        if (signer == address(0)) revert GasTank__recoverSignature_invalidSigner();
    }

    function transfer(Safe safe, address token, address payable to, uint256 amount) private {
        if (token == address(0)) {
            // solium-disable-next-line security/no-send
            bool result = safe.execTransactionFromModule(to, amount, "", Enum.Operation.Call);
            if (!result) revert GasTank__transfer_ETH();
        } else {
            bytes memory data = abi.encodeWithSignature("transfer(address,uint256)", to, amount);
            bool result = safe.execTransactionFromModule(token, 0, data, Enum.Operation.Call);
            if (!result) revert GasTank__transfer_ERC20();
        }
    }
}
