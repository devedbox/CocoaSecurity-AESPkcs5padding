//
//  CocoaSecurity+AESPkcs5padding.h
//  CocoaSecurity+AESPkcs5padding
//
//  Created by ai on 16/4/11.
//  Copyright © 2016年 devedbox. All rights reserved.
//

#import <CocoaSecurity/CocoaSecurity.h>

@interface CocoaSecurity(AESPkcs5padding)
+ (CocoaSecurityResult *)aesPkcs5paddingEncrypt:(NSString *)data key:(NSString *)key;
+ (CocoaSecurityResult *)aesPkcs5paddingEncrypt:(NSString *)data hexKey:(NSString *)key hexIv:(NSString *)iv;
+ (CocoaSecurityResult *)aesPkcs5paddingEncrypt:(NSString *)data key:(NSData *)key iv:(NSData *)iv;
+ (CocoaSecurityResult *)aesPkcs5paddingEncryptWithData:(NSData *)data key:(NSData *)key iv:(NSData *)iv;
@end