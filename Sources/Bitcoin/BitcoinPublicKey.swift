// Copyright © 2017-2018 Trust.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

import Foundation

public final class BitcoinPublicKey: PublicKey {
    /// Validates that raw data is a valid public key.
    static public func isValid(data: Data) -> Bool {
        if data.count != 65 {
            return false
        }
        return true
    }
    
    /// Coin this key is for.
    public let coin = Coin.bitcoin
    
    /// Raw representation of the public key.
    public let data: Data
    
    /// Address.
    public var address: Address {
        let publicKeyStr = data.hexString
        let publicKeySubstr = publicKeyStr.prefix(66)
        let publicKeyHead = String(format: "%02d", Int(publicKeySubstr.prefix(2))! - 2)
        let publicKeyFoot = publicKeySubstr.suffix(64)
        let publicKey = Data(hexString: publicKeyHead + publicKeyFoot)!
        let hash1 = Crypto.sha256ripemd160(publicKey)
#if DEBUG || TEST
        let extended = Data([Bitcoin.TestNet.publicKeyHashAddressPrefix]) + hash1
#else
        let extended = Data([Bitcoin.MainNet.publicKeyHashAddressPrefix]) + hash1
#endif
        let hash2 = Crypto.sha256sha256(extended)
        let checksum = hash2.hexString.prefix(8)
        let binAddress = Data(hexString: extended.hexString + checksum)!

        //  Base58 encoding
        let alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        var bytes = binAddress
        var zerosCount = 0
        var length = 0
        for b in bytes {
            if b != 0 { break }
            zerosCount += 1
        }
        bytes.removeFirst(zerosCount)
        let size = bytes.count * 138 / 100 + 1
        var base58: [UInt8] = Array(repeating: 0, count: size)
        for b in bytes {
            var carry = Int(b)
            var i = 0
            for j in 0...base58.count - 1 where carry != 0 || i < length {
                carry += 256 * Int(base58[base58.count - j - 1])
                base58[base58.count - j - 1] = UInt8(carry % 58)
                carry /= 58
                i += 1
            }
            assert(carry == 0)
            length = i
        }
        var zerosToRemove = 0
        var str = ""
        for b in base58 {
            if b != 0 { break }
            zerosToRemove += 1
        }
        base58.removeFirst(zerosToRemove)
        while 0 < zerosCount {
            str = "\(str)1"
            zerosCount -= 1
        }
        for b in base58 {
            str = "\(str)\(alphabet[String.Index(encodedOffset: Int(b))])"
        }
        print("Base58 encoding of 8", str)
        return BitcoinAddress(string: str)!
    }
    
    /// Creates a public key from a raw representation.
    public init?(data: Data) {
        if !BitcoinPublicKey.isValid(data: data) {
            return nil
        }
        self.data = data
    }
    
    public var description: String {
        return address.description
    }
}
