// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.21;

import { Enum } from "safe-contracts/contracts/common/Enum.sol";
import { Safe } from "safe-contracts/contracts/Safe.sol";
import { SafeStorage } from "safe-contracts/contracts/libraries/SafeStorage.sol";

import { GelatoRelayContextERC2771 } from "@gelatonetwork/relay-context/contracts/GelatoRelayContextERC2771.sol";
import { TokenUtils } from "@gelatonetwork/relay-context/contracts/lib/TokenUtils.sol";

import { Address } from "@openzeppelin/contracts/utils/Address.sol";
import { EnumerableSet } from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract GasTankModule is SafeStorage, Ownable, GelatoRelayContextERC2771 {
    using TokenUtils for address;
    using EnumerableSet for EnumerableSet.AddressSet;

    address public immutable moduleAddress;

    address internal constant SENTINEL_MODULES = address(0x1);

    address internal constant EL_DIEGO = address(0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE);

    string public constant name = "GasTankModule";

    string public constant version = "1";

    uint24 public constant DENOMINATOR = 100_000; // 1000 * 100

    address payable public treasury;

    uint24 public adminFeePercentage;

    /// 100% = 100_000 | 10% = 10_000 | 1% = 1_000 | 0.1% = 100 | 0.01% = 10

    bytes32 public constant ALLOWED_FEE_TYPEHASH =
        keccak256("AllowedFee(address gasTank,address token,uint256 maxFee,uint16 nonce)");

    mapping(address gasTank => mapping(address signer => uint16 signerNonce)) public nonces;

    mapping(address gasTank => EnumerableSet.AddressSet) internal delegates;

    mapping(address delegate => EnumerableSet.AddressSet) internal delegatedGasTanks;

    // index 0 is used for no when delegate is not a real delegate
    mapping(address gasTank => mapping(address delegate => mapping(uint16 index => EnumerableSet.AddressSet))) internal
        tokens;

    mapping(address gasTank => mapping(address delegate => uint16 index)) internal delegatesCurrentIndex;

    ////////////////////////////
    ////////// EVENTS //////////
    ////////////////////////////

    event SetAdminFeePercentage(uint24 adminFeePercentage);
    event SetTreasury(address treasury);
    event AddDelegate(address indexed safe, address delegate);
    event RemoveDelegate(address indexed safe, address delegate);
    event AddTokenAllowance(address indexed safe, address indexed delegate, address indexed token);
    event RemoveTokenAllowance(address indexed safe, address indexed delegate, address indexed token);
    event GetFeesFromOwner(address indexed safe, address indexed owner, address token, uint256 relayerFee);
    event GetFeesFromDelegate(address indexed safe, address indexed delegate, address token, uint256 relayerFee);

    ////////////////////////////
    ////////// ERRORS //////////
    ////////////////////////////

    error GasTankModule__enableMyself_notDELEGATECALL();
    error GasTankModule__setAdminFeePercentage_invalidPercentage();
    error GasTankModule__getFee_notOwnerOrDelegate();
    error GasTankModule__getFee_maxFee();
    error GasTankModule__getFees_invalidSigner();
    error GasTankModule__addDelegate_invalidDelegate();
    error GasTankModule__removeDelegate_invalidDelegate();
    error GasTankModule__addDelegate_alreadyDelegate();
    error GasTankModule__setTokenAllowance_invalidDelegate();
    error GasTankModule__setTokenAllowance_notDelegate();
    error GasTankModule__removeTokenAllowance_invalidDelegate();
    error GasTankModule__removeTokenAllowance_notDelegate();
    error GasTankModule__recoverSignature_invalidSigner();
    error GasTankModule__transfer_ETH();
    error GasTankModule__transfer_ERC20();

    /////////////////////////////////
    ////////// CONSTRUCTOR //////////
    /////////////////////////////////

    constructor(address _admin) {
        _transferOwnership(_admin);
        moduleAddress = address(this);
    }

    ///////////////////////////////
    ////////// EXTERNALS //////////
    ///////////////////////////////

    //solhint-disable-next-line func-name-mixedcase
    function DOMAIN_SEPARATOR() external view returns (bytes32) {
        return _getDomainSeparator();
    }

    function enableMyself() external {
        if (moduleAddress == address(this)) revert GasTankModule__enableMyself_notDELEGATECALL();

        // Module cannot be added twice.
        require(modules[moduleAddress] == address(0), "GS102");
        modules[moduleAddress] = modules[SENTINEL_MODULES];
        modules[SENTINEL_MODULES] = moduleAddress;
    }

    /// @notice Set the admin fee percentage
    /// @param _adminFeePercentage The new admin fee percentage
    function setAdminFeePercentage(uint24 _adminFeePercentage) external onlyOwner {
        if (_adminFeePercentage > DENOMINATOR) revert GasTankModule__setAdminFeePercentage_invalidPercentage();

        adminFeePercentage = _adminFeePercentage;
        emit SetAdminFeePercentage(_adminFeePercentage);
    }

    /// @notice Set the treasury address
    /// @param _treasury The new treasury address
    function setTreasury(address payable _treasury) external onlyOwner {
        treasury = _treasury;
        emit SetTreasury(_treasury);
    }

    function execTransaction(
        address _gasTank,
        address _safe,
        bytes memory _txData,
        uint256 _maxFee,
        bytes memory _feeSignature
    )
        public
        onlyGelatoRelayERC2771
        returns (bool success)
    {
        _payFee(_gasTank, _maxFee, _feeSignature);

        bool returnData = abi.decode(Address.functionCall(_safe, _txData), (bool));

        return returnData;
    }

    /// @dev Allows to add a delegate.
    /// @param delegate Delegate that should be added.
    function addDelegate(address delegate) external {
        if (delegate == address(0)) revert GasTankModule__addDelegate_invalidDelegate();
        if (delegates[msg.sender].contains(delegate)) revert GasTankModule__addDelegate_alreadyDelegate();

        delegates[msg.sender].add(delegate);
        delegatedGasTanks[delegate].add(msg.sender);
        delegatesCurrentIndex[msg.sender][delegate] += 1;

        emit AddDelegate(msg.sender, delegate);
    }

    /// @dev Allows to remove a delegate.
    /// @param delegate Delegate that should be removed.
    function removeDelegate(address delegate) external {
        if (delegate == address(0)) revert GasTankModule__removeDelegate_invalidDelegate();

        delegates[msg.sender].remove(delegate);
        delegatedGasTanks[delegate].remove(msg.sender);

        emit RemoveDelegate(msg.sender, delegate);
    }

    /// @dev Allows to update the allowance for a specified token. This can only be done via a Safe transaction.
    /// @param delegate Delegate whose allowance should be updated.
    /// @param token Token contract address.
    function addTokenAllowance(address delegate, address token) external {
        if (delegate == address(0)) revert GasTankModule__setTokenAllowance_invalidDelegate();
        if (!delegates[msg.sender].contains(delegate)) revert GasTankModule__setTokenAllowance_notDelegate();

        uint16 currentIndex = delegatesCurrentIndex[msg.sender][delegate];

        tokens[msg.sender][delegate][currentIndex].add(token);

        emit AddTokenAllowance(msg.sender, delegate, token);
    }

    function removeTokenAllowance(address delegate, address token) external {
        if (delegate == address(0)) revert GasTankModule__removeTokenAllowance_invalidDelegate();
        if (!delegates[msg.sender].contains(delegate)) revert GasTankModule__removeTokenAllowance_notDelegate();

        uint16 currentIndex = delegatesCurrentIndex[msg.sender][delegate];

        tokens[msg.sender][delegate][currentIndex].remove(token);

        emit RemoveTokenAllowance(msg.sender, delegate, token);
    }

    /////////////////////////////
    ////////// PUBLICS //////////
    /////////////////////////////

    function getDelegates(address safe) public view returns (address[] memory) {
        return delegates[safe].values();
    }

    function getDelegatedSafes(address delegate) public view returns (address[] memory) {
        return delegatedGasTanks[delegate].values();
    }

    function isDelegate(address safe, address delegate) public view returns (bool) {
        return delegates[safe].contains(delegate);
    }

    function getTokens(address safe, address delegate) public view returns (address[] memory) {
        uint16 currentIndex = delegates[safe].contains(delegate) ? delegatesCurrentIndex[safe][delegate] : 0;

        return tokens[safe][delegate][currentIndex].values();
    }

    /// @dev Generates the transfer hash that should be signed to authorize a transfer
    function generateTransferHash(
        address safe,
        address token,
        uint96 amount,
        uint16 signerNonce
    )
        public
        view
        returns (bytes32)
    {
        return keccak256(_generateTransferHashData(safe, token, amount, signerNonce));
    }

    ///////////////////////////////
    ////////// INTERNALS //////////
    ///////////////////////////////

    function _payFee(address _gasTank, uint256 _maxFee, bytes memory _feeSignature) internal {
        address feeToken = _getFeeToken();
        uint256 relayerFee = _getFee();

        address sender = _getMsgSender();
        uint16 signerNonce = nonces[_gasTank][sender];
        bytes memory transferHashData = _generateTransferHashData(address(_gasTank), feeToken, _maxFee, signerNonce);

        // Update nonce
        nonces[_gasTank][sender] += 1;

        // Check signature
        (address signer, ECDSA.RecoverError error) = ECDSA.tryRecover(keccak256(transferHashData), _feeSignature);

        if (error != ECDSA.RecoverError.NoError || sender != signer) revert GasTankModule__getFees_invalidSigner();

        // check signer is owner or delegate
        if (!_isOwnerOrDelegate(_gasTank, signer, feeToken)) revert GasTankModule__getFee_notOwnerOrDelegate();

        uint256 totalFee = relayerFee;
        uint256 adminFeeAmount;

        if (treasury != address(0) && adminFeePercentage > 0) {
            adminFeeAmount = (relayerFee * adminFeePercentage) / DENOMINATOR;
            totalFee += adminFeeAmount;
        }

        if (totalFee > _maxFee) revert GasTankModule__getFee_maxFee();

        // Transfer fee from safe to this contract
        _pullFee(Safe(payable(_gasTank)), feeToken, payable(address(this)), totalFee);

        // Transfer admin fee from this contract to treasury
        if (adminFeeAmount > 0) feeToken.transfer(treasury, adminFeeAmount);

        // Payment to Gelato
        _transferRelayFee();
    }

    /// @dev Generates the data for the transfer hash (required for signing)
    function _generateTransferHashData(
        address safe,
        address token,
        uint256 amount,
        uint16 signerNonce
    )
        internal
        view
        returns (bytes memory)
    {
        bytes32 transferHash = keccak256(abi.encode(ALLOWED_FEE_TYPEHASH, safe, token, amount, signerNonce));
        return abi.encodePacked("\x19\x01", _getDomainSeparator(), transferHash);
    }

    function _isOwnerOrDelegate(address _gasTank, address _signer, address _feeToken) internal view returns (bool) {
        if (Safe(payable(_gasTank)).isOwner(_signer)) {
            return true;
        }

        uint16 currentIndex = delegatesCurrentIndex[_gasTank][_signer];
        if (delegates[_gasTank].contains(_signer) && tokens[_gasTank][_signer][currentIndex].contains(_feeToken)) {
            return true;
        }

        return false;
    }

    function _pullFee(Safe safe, address token, address payable to, uint256 amount) internal {
        if (token == address(0) || token == EL_DIEGO) {
            // solium-disable-next-line security/no-send
            bool result = safe.execTransactionFromModule(to, amount, "", Enum.Operation.Call);
            if (!result) revert GasTankModule__transfer_ETH();
        } else {
            bytes memory data = abi.encodeWithSelector(IERC20.transfer.selector, to, amount);
            bool result = safe.execTransactionFromModule(token, 0, data, Enum.Operation.Call);
            if (!result) revert GasTankModule__transfer_ERC20();
        }
    }

    function _getDomainSeparator() internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256(
                    bytes(
                        //solhint-disable-next-line max-line-length
                        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                    )
                ),
                keccak256(bytes(name)),
                keccak256(bytes(version)),
                block.chainid,
                address(this)
            )
        );
    }

    ///////////////////////////////////////
    ////////// SHOW ME THE MONEY //////////
    ///////////////////////////////////////

    receive() external payable { }
}
