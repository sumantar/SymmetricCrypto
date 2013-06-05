//
//  GASymmetricCrypto.m
//  CryptoSample
//
//  Created by sumantar on 02/05/13.
//  Copyright (c) 2013 sumantar. All rights reserved.
//

/*
 Rererence from apple sample application of using iOS cryptographic API.
 http://developer.apple.com/library/ios/#samplecode/CryptoExercise/Introduction/Intro.html
 */

#import "SRSymmetricCrypto.h"
#import <Security/Security.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>

#define kChosenCipherBlockSize	kCCBlockSizeAES128
#define kChosenCipherKeySize	kCCKeySizeAES128

#define LengthOfArray(x) (sizeof(x)/sizeof(*(x)))
static char encTable[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static char decTable[128];

//This is the category to convert NSData to NSString and vice-versa
@interface NSData(Coversion)

//Override initialize method
+ (void) initialize;

//Convert NSString to NSData
+ (NSData *) convertStringToData:(NSString *)stringToConvert;

//Convert NSData to NSString
+ (NSString *) convertDataToString:(NSData *)dataToConvert;
@end

@implementation NSData(Coversion)

+ (void) initialize
{
	if (self == [NSData class]) {
		memset(decTable, 0, LengthOfArray(decTable));
		for (NSInteger length = 0; length < LengthOfArray(encTable); length++) {
			decTable[encTable[length]] = length;
		}
	}
}

//Convert NSString to NSData
+ (NSData *) convertStringToData:(NSString *)stringToConvert{
    const char *charString = (char *)[stringToConvert cStringUsingEncoding:NSASCIIStringEncoding];
    NSInteger inputStringLength = stringToConvert.length;
    
    if ((charString == NULL) || (inputStringLength % 4 != 0)) {
		return nil;
	}
	
	while (inputStringLength > 0 && charString[inputStringLength - 1] == '=') {
		inputStringLength--;
	}
	
	NSInteger outputLength = inputStringLength * 3 / 4;
	NSMutableData* data = [NSMutableData dataWithLength:outputLength];
	uint8_t* output = data.mutableBytes;
	
	NSInteger inputPoint = 0;
	NSInteger outputPoint = 0;
	while (inputPoint < inputStringLength) {
		char input0 = charString[inputPoint++];
		char input1 = charString[inputPoint++];
		char input2 = inputPoint < inputStringLength ? charString[inputPoint++] : 'A';
		char input3 = inputPoint < inputStringLength ? charString[inputPoint++] : 'A';
		
		output[outputPoint++] = (decTable[input0] << 2) | (decTable[input1] >> 4);
		if (outputPoint < outputLength) {
			output[outputPoint++] = ((decTable[input1] & 0xf) << 4) | (decTable[input2] >> 2);
		}
		if (outputPoint < outputLength) {
			output[outputPoint++] = ((decTable[input2] & 0x3) << 6) | decTable[input3];
		}
	}
	
	return data;
}

//Convert NSData to NSString
+ (NSString *) convertDataToString:(NSData *)dataToConvert{
    NSInteger inputDataLength = dataToConvert.length;
    const uint8_t* input = (uint8_t*) dataToConvert.bytes;
    
    NSMutableData* data = [NSMutableData dataWithLength:((inputDataLength + 2) / 3) * 4];
    uint8_t* output = (uint8_t*)data.mutableBytes;
    
    for (NSInteger loop = 0; loop < inputDataLength; loop += 3) {
        NSInteger value = 0;
        for (NSInteger innerLoop = loop; innerLoop < (loop + 3); innerLoop++) {
            value <<= 8;
            
            if (innerLoop < inputDataLength) {
                value |= (0xFF & input[innerLoop]);
            }
        }
        
        NSInteger index = (loop / 3) * 4;
        output[index + 0] =                    encTable[(value >> 18) & 0x3F];
        output[index + 1] =                    encTable[(value >> 12) & 0x3F];
        output[index + 2] = (loop + 1) < inputDataLength ? encTable[(value >> 6)  & 0x3F] : '=';
        output[index + 3] = (loop + 2) < inputDataLength ? encTable[(value >> 0)  & 0x3F] : '=';
    }
    
    return [[NSString alloc] initWithData:data encoding:NSASCIIStringEncoding];
}

@end

@implementation SRSymmetricCrypto

//Get encrypted data using symentric key encryption
- (NSString *) symmetricEncryption:(NSString *)plainText{
    
    NSData *plainTextData = [plainText dataUsingEncoding:NSASCIIStringEncoding];
    CCOptions padding = kCCOptionPKCS7Padding;
    NSData *encryptedData = [self encrypt:plainTextData key:[self symmetricKey] padding:&padding];
    return [NSData convertDataToString:encryptedData];
    
}

//Get plain text data using symentric key decryption
- (NSString *) symmetricDecryption:(NSString *)cypherText{
    
    NSData *encryptedData = [NSData convertStringToData:cypherText];
    CCOptions padding = kCCOptionPKCS7Padding;
    NSData *data = [self decrypt:encryptedData key:[self symmetricKey] padding:&padding];
    return [[NSString alloc] initWithData:data encoding:NSASCIIStringEncoding];
}

//Generate symmetric key from applcation bundle and version
- (NSData *) symmetricKey{
    NSDictionary *infoDictionary = [[NSBundle mainBundle] infoDictionary];
    NSString *shortBundleName = [infoDictionary objectForKey:@"CFBundleName"];    
#ifdef LOGIC_TESTING
    shortBundleName = @"BankApp";
#endif
    return [self generateMD5Data:shortBundleName];
}

- (NSData *) encrypt:(NSData *)plainText key:(NSData *)symmetricKey padding:(CCOptions *)pkcs7 {
    return [self doCipher:plainText key:symmetricKey context:kCCEncrypt padding:pkcs7];
}

- (NSData *) decrypt:(NSData *)plainText key:(NSData *)symmetricKey padding:(CCOptions *)pkcs7 {
    return [self doCipher:plainText key:symmetricKey context:kCCDecrypt padding:pkcs7];
}

- (NSData *) doCipher:(NSData *)plainText key:(NSData *)symmetricKey
             context:(CCOperation)encryptOrDecrypt padding:(CCOptions *)pkcs7 {
    
    CCCryptorStatus ccStatus = kCCSuccess;
    
    // Symmetric crypto reference.
    CCCryptorRef thisEncipher = NULL;
    
    // Cipher Text container.
    NSData * cipherOrPlainText = nil;
    
    // Pointer to output buffer.
    uint8_t * bufferPtr = NULL;
    
    // Total size of the buffer.
    size_t bufferPtrSize = 0;
    
    // Remaining bytes to be performed on.
    size_t remainingBytes = 0;
    
    // Number of bytes moved to buffer.
    size_t movedBytes = 0;
    
    // Length of plainText buffer.
    size_t plainTextBufferSize = 0;
    
    // Placeholder for total written.
    size_t totalBytesWritten = 0;
    
    // A friendly helper pointer.
    uint8_t * ptr = nil;
    
    // Initialization vector; dummy in this case 0's.
    uint8_t iv[kChosenCipherBlockSize];
    memset((void *) iv, 0x0, (size_t) sizeof(iv));
    
    plainTextBufferSize = [plainText length];
    
    // We don't want to toss padding on if we don't need to
    if(encryptOrDecrypt == kCCEncrypt) {
        if(*pkcs7 != kCCOptionECBMode) {
            if((plainTextBufferSize % kChosenCipherBlockSize) == 0) {
                *pkcs7 = 0x0000;
            } else {
                *pkcs7 = kCCOptionPKCS7Padding;
            }
        }
    } else if(encryptOrDecrypt != kCCDecrypt) {
        //Invalid CCOperation parameter
    }
    
    // Create and Initialize the crypto reference.
    CCCryptorCreate(encryptOrDecrypt,
                               kCCAlgorithmAES128,
                               *pkcs7,
                               (const void *)[symmetricKey bytes],
                               kChosenCipherKeySize,
                               (const void *)iv,
                               &thisEncipher
                               );
    
    // Calculate byte block alignment for all calls through to and including final.
    bufferPtrSize = CCCryptorGetOutputLength(thisEncipher, plainTextBufferSize, true);
    
    // Allocate buffer.
    bufferPtr = malloc(bufferPtrSize * sizeof(uint8_t));
    
    // Zero out buffer.
    memset((void *)bufferPtr, 0x0, bufferPtrSize);
    
    // Initialize some necessary book keeping.
    ptr = bufferPtr;
    
    // Set up initial size.
    remainingBytes = bufferPtrSize;
    
    // Actually perform the encryption or decryption.
    CCCryptorUpdate(thisEncipher,
                               (const void *) [plainText bytes],
                               plainTextBufferSize,
                               ptr,
                               remainingBytes,
                               &movedBytes
                               );
    
    // Handle book keeping.
    ptr += movedBytes;
    remainingBytes -= movedBytes;
    totalBytesWritten += movedBytes;
    
    // Finalize everything to the output buffer.
    ccStatus = CCCryptorFinal(thisEncipher,
                              ptr,
                              remainingBytes,
                              &movedBytes
                              );
    
    totalBytesWritten += movedBytes;
    
    if(thisEncipher) {
        (void) CCCryptorRelease(thisEncipher);
        thisEncipher = NULL;
    }
    
    /*enum {
     kCCSuccess = 0,
     kCCParamError = -4300,
     kCCBufferTooSmall = -4301,
     kCCMemoryFailure = -4302,
     kCCAlignmentError = -4303,
     kCCDecodeError = -4304,
     kCCUnimplemented = -4305
     };
     typedef int32_t CCCryptorStatus;
     */
    
    if (ccStatus == kCCSuccess)
        cipherOrPlainText = [NSData dataWithBytes:(const void *)bufferPtr length:(NSUInteger)totalBytesWritten];
    else
        cipherOrPlainText = nil;
    
    if(bufferPtr) free(bufferPtr);
    
    return cipherOrPlainText;
}

// Get MD5 Hash for an input string
- (NSData*) generateMD5Data:(NSString *)key
{
	// Create pointer to the string as UTF8
	const char *ptr = [key UTF8String];
    
	// Create byte array of unsigned chars
	unsigned char md5Buffer[CC_MD5_DIGEST_LENGTH];
    
	// Create 16 byte MD5 hash value, store in buffer
	CC_MD5(ptr, strlen(ptr), md5Buffer);
    
	NSData	*data = [NSData dataWithBytes:(const void *)md5Buffer length:sizeof(unsigned char)*CC_MD5_DIGEST_LENGTH];
    
	return data;
}

@end
