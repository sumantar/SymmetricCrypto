//
//  GASymmetricCrypto.h
//  CryptoSample
//
//  Created by sumantar on 02/05/13.
//  Copyright (c) 2013 sumantar. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface SRSymmetricCrypto : NSObject
//Get encrypted data using symentric key encryption
- (NSString *) symmetricEncryption:(NSString *)plainText;

//Get plain text data using symentric key decryption
- (NSString *) symmetricDecryption:(NSString *)cypherText;
@end