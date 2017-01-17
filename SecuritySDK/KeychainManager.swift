//
//  KeychainManager.swift
//  SecuritySDK
//
//  Created by Jay on 1/13/17.
//  Copyright © 2017 Jay. All rights reserved.
//

import Foundation
import Security

struct KeychainManager {
    
    static func createAccountWith(name:String,
                                  accessType:AccessType,
                                  accountType:AccountType,
                                  completion:@escaping(Result<(Bool)>)->Void) {
        let keychainItem = NSMutableDictionary()
        let defaultPassword = "good things start here!"
        keychainItem[kSecClass] = kSecClassInternetPassword
        keychainItem[kSecAttrAccessible] = accessType.rawValue as CFString
        keychainItem[kSecAttrServer] = accountType.rawValue as CFString
        keychainItem[kSecAttrAccount] = name as CFString
        if SecItemCopyMatching(keychainItem as CFDictionary, nil) == noErr {
            completion(.failure("Account is already existed."))
        }else {
            let data = defaultPassword.data(using: String.Encoding(rawValue:4))
            keychainItem[kSecValueData] = data!
            let sts:OSStatus = SecItemCopyMatching(keychainItem as CFDictionary, nil)
            if sts == noErr {
                completion(.success)
            }else {
                completion(.failure("System error, error code:\(sts)."))
            }
        }
    }
    
    static func updatePasswordForAccount(named:String,
                                         password:String,
                                         accessType:AccessType,
                                         completion:@escaping(Result<(Bool)>)->Void){
        let keychainItem = NSMutableDictionary()
        keychainItem[kSecClass] = kSecClassInternetPassword
        keychainItem[kSecAttrAccessible] = accessType.rawValue as CFString
        keychainItem[kSecAttrAccount] = named as CFString
        if SecItemCopyMatching(keychainItem as CFDictionary, nil) == noErr {
            let updatedDic = NSMutableDictionary()
            updatedDic[kSecValueData] = password.data(using: String.Encoding(rawValue:4))
            let sts:OSStatus = SecItemUpdate(keychainItem as CFDictionary, updatedDic as CFDictionary)
            if sts == noErr {
                completion(.success)
            }else {
                completion(.failure("System error, error code:\(sts)."))
            }
        }else {
            completion(.failure("Account does not exist."))
        }
    }
    
    static func authenticateUserWith(userName:String, password:String, accessType:AccessType, completion:@escaping(Result<(Bool)>)->Void) {
        let keychainItem = NSMutableDictionary()
        keychainItem[kSecClass] = kSecClassInternetPassword
        keychainItem[kSecAttrAccessible] = accessType.rawValue as CFString
        keychainItem[kSecAttrAccount] = userName as CFString
        keychainItem[kSecReturnData] = kCFBooleanTrue
        keychainItem[kSecReturnAttributes] = kCFBooleanTrue
        var result:AnyObject?
        if SecItemCopyMatching(keychainItem as CFDictionary, &result) == noErr {
            let resultDict = result as! [String:Any]
            let passData = resultDict[kSecValueData as String] as! Data
            let passPhase = String(data:passData, encoding: String.Encoding(rawValue:4))
            if passPhase! == password {
                completion(.success)
            }else {
                completion(.failure("Password is not right."))
            }
        }else {
            completion(.failure("Account does not exist."))
        }
    }
    
    static func deleteAccount(userName:String, accessType:AccessType, completion:@escaping(Result<(Bool)>)->Void) {
        let keychainItem = NSMutableDictionary()
        keychainItem[kSecClass] = kSecClassInternetPassword
        keychainItem[kSecAttrAccessible] = accessType.rawValue as CFString
        keychainItem[kSecAttrAccount] = userName as CFString
        if SecItemCopyMatching(keychainItem as CFDictionary, nil) == noErr {
            let sts = SecItemDelete(keychainItem as CFDictionary)
            if sts == noErr {
                completion(.success)
            }else {
                completion(.failure("Error Code:\(sts)"))
            }
        }else {
            completion(.failure("Account does not exist."))
        }
    }
}

public enum AccessType:String {
    case onlyWhenUserUnlockDevice = "ak"
    case unlockedOnce = "ck"
    case always = "dk"
    case thisDeviceOnly = "dku"
    case thisDeviceUnlockedOnly = "aku"
    case thisDeviceUnlockedOnceOnly = "cku"
}

public enum AccountType:String {
    case host = "host"
    case admin = "admin"
    case user = "user"
    
    static func matchRawValue(rawValue:String)->AccountType {
        if rawValue == "host" {
            return .host
        }else if rawValue == "admin" {
            return .admin
        }else {
            return .user
        }
    }
}

public enum Result<T> {
    case successWith(AccountType)
    case success
    case failure(String)
}
