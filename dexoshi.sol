// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC1155/extensions/ERC1155URIStorage.sol";

contract Dexoshi is ERC1155URIStorage {
    // Set default uri
    string private constant DEFAULT_URI = "@dexoshi";

    // Admin is allowed to call functions on behalf of user
    address private constant ADMIN = 0xdA064B1Cef52e19caFF22ae2Cc1A4e8873B8bAB0;

    // Non-custodial addresses. Admin cannot transfer/burn on behalf of user
    mapping (address => bool) public hasCustody;

    constructor() ERC1155(DEFAULT_URI) {}

    /*
    * Optional: Converts twitter id to address https://developer.twitter.com/en/docs/twitter-ids
    * Twitter handle to twitter ID: https://www.codeofaninja.com/tools/find-twitter-id/
    * @param _twitterId twitter identifier
    * @example 1215122943765774337 returns 0x29FA969D379DB911095E7fc45133C39D24Af7eE6
    */
    function twitterIdToAddress(uint64 _twitterId) public pure returns(address) {
        return address(bytes20(sha256(abi.encodePacked(_twitterId))));
    }

    /*
    * Toggle address custody
    * @param _bool true  = user HAS          custody. Admin CANNOT move tokens. User PAYS       for gas
    * @param _bool false = user DOESN'T have custody. Admin CAN    move tokens. User DOES'T pay for gas
    * Default is false
    */
    function setCustody(bool _bool) public {
        hasCustody[tx.origin] = _bool;
    }

    /*
    * Only admin can mint
    * @param _to address to transfer to
    * @param _tokenId token identifier
    * @param _amount of tokens to mint
    * @param _tokenURI uri to metadata json object
    */
    function adminMint(address _to, uint256 _tokenId, uint256 _amount, string memory _tokenURI) public {
        require(msg.sender == ADMIN, "Only admin can mint");
        // if this tokenId has never been minted, then set URI
        if (keccak256(abi.encodePacked(uri(_tokenId))) == keccak256(abi.encodePacked(DEFAULT_URI))) _setURI(_tokenId, _tokenURI);
        _mint(_to, _tokenId, _amount, "");
    }

    /*
    * Only admin with custody can transfer
    * @params _from address. Admin cannot transfer if from address has custody
    * @params _to address to transfer to
    * @params _tokenId token identifier
    * @params _amount of tokens to transfer
    */
    function adminSafeTransferFrom(address _from, address _to, uint256 _tokenId, uint256 _amount) public {
        require(msg.sender == ADMIN, "Only admin can transfer");
        require(hasCustody[_from] == false, "Admin does not have custody");
        _safeTransferFrom(_from, _to, _tokenId, _amount, "");
    }

    /*
    * Only admin with custody can batch transfer
    * @params _from address. Admin cannot transfer if from address has custody
    * @params _to address to transfer to
    * @params _tokenIds list of tokens
    * @params _amounts list of amounts
    */
    function adminSafeBatchTransferFrom(address _from, address _to, uint256[] memory _tokenIds, uint256[] memory _amounts) public {
        require(msg.sender == ADMIN, "Only admin can burn");
        require(hasCustody[_from] == false, "Admin does not have custody");
        _safeBatchTransferFrom(_from, _to, _tokenIds, _amounts, "");
    }

    /*
    * Only admin with custody can burn
    * @params _from address. Admin cannot burn if from address has custody
    * @params _tokenId token identifier
    * @params _amount of tokens to burn
    */
    function adminBurn(address _from, uint256 _tokenId, uint256 _amount) public {
        require(msg.sender == ADMIN, "Only admin can burn");
        require(hasCustody[_from] == false, "Admin does not have custody");
        _burn(_from, _tokenId, _amount);
    }

}
