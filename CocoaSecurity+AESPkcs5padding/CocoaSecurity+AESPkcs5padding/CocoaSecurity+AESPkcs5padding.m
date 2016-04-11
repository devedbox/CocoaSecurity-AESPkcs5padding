//
//  CocoaSecurity+AESPkcs5padding.m
//  CocoaSecurity+AESPkcs5padding
//
//  Created by ai on 16/4/11.
//  Copyright © 2016年 devedbox. All rights reserved.
//

#import "CocoaSecurity+AESPkcs5padding.h"
#import <CommonCrypto/CommonHMAC.h>
#import <CommonCrypto/CommonCryptor.h>
#import "Base64.h"

@implementation CocoaSecurity(AESPkcs5padding)
+ (CocoaSecurityResult *)aesPkcs5paddingEncrypt:(NSString *)data key:(NSString *)key {
    CocoaSecurityResult * sha = [self sha384:key];
    NSData *aesKey = [sha.data subdataWithRange:NSMakeRange(0, 32)];
    NSData *aesIv = [sha.data subdataWithRange:NSMakeRange(32, 16)];
    
    return [self aesPkcs5paddingEncrypt:data key:aesKey iv:aesIv];
}
+ (CocoaSecurityResult *)aesPkcs5paddingEncrypt:(NSString *)data hexKey:(NSString *)key hexIv:(NSString *)iv {
    CocoaSecurityDecoder *decoder = [CocoaSecurityDecoder new];
    NSData *aesKey = [decoder hex:key];
    NSData *aesIv = [decoder hex:iv];
    
    return [self aesPkcs5paddingEncrypt:data key:aesKey iv:aesIv];
}
+ (CocoaSecurityResult *)aesPkcs5paddingEncrypt:(NSString *)data key:(NSData *)key iv:(NSData *)iv {
    return [self aesPkcs5paddingEncryptWithData:[data dataUsingEncoding:NSUTF8StringEncoding] key:key iv:iv];
}

+ (CocoaSecurityResult *)aesPkcs5paddingEncryptWithData:(NSData *)data key:(NSData *)key iv:(NSData *)iv
{
    // check length of key and iv
    if ([iv length] != 16) {
        @throw [NSException exceptionWithName:@"Cocoa Security"
                                       reason:@"Length of iv is wrong. Length of iv should be 16(128bits)"
                                     userInfo:nil];
    }
    if ([key length] != 16 && [key length] != 24 && [key length] != 32 ) {
        @throw [NSException exceptionWithName:@"Cocoa Security"
                                       reason:@"Length of key is wrong. Length of iv should be 16, 24 or 32(128, 192 or 256bits)"
                                     userInfo:nil];
    }
    
    // setup output buffer
    size_t bufferSize = [data length] + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    
    // do encrypt
    size_t encryptedSize = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt,
                                          kCCAlgorithmAES128,
                                          kCCOptionPKCS7Padding | kCCOptionECBMode,
                                          [key bytes],     // Key
                                          [key length],    // kCCKeySizeAES
                                          [iv bytes],       // IV
                                          [data bytes],
                                          [data length],
                                          buffer,
                                          bufferSize,
                                          &encryptedSize);
    if (cryptStatus == kCCSuccess) {
        CocoaSecurityResult *result = [[CocoaSecurityResult alloc] initWithBytes:buffer length:encryptedSize];
        free(buffer);
        
        return result;
    }
    else {
        free(buffer);
        @throw [NSException exceptionWithName:@"Cocoa Security"
                                       reason:@"Encrypt Error!"
                                     userInfo:nil];
        return nil;
    }
}
@end