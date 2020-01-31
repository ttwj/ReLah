#import <CommonCrypto/CommonCrypto.h>
#import <Security/SecKey.h>
#import <substrate.h>

// Hook CCCrypt()


static OSStatus (*original_SecKeyEncrypt) (
                       SecKeyRef           key,
                       SecPadding          padding,
                       const uint8_t        *plainText,
                       size_t              plainTextLen,
                       uint8_t             *cipherText,
                                           size_t              *cipherTextLen);

static OSStatus replaced_SecKeyEncrypt(
                              SecKeyRef           key,
                              SecPadding          padding,
                              const uint8_t        *plainText,
                              size_t              plainTextLen,
                              uint8_t             *cipherText,
                              size_t              *cipherTextLen) {
    
    NSLog(@"calling replaced SecKeyPadding %u, plainTextLen %lu, cipherTextLen %lu", padding, plainTextLen, (unsigned long)cipherTextLen);
    return original_SecKeyEncrypt(key, padding, plainText, plainTextLen, cipherText, cipherTextLen);
    
}

static CCCryptorStatus (*original_CCCrypt)(
                                           CCOperation op,
                                           CCAlgorithm alg,
                                           CCOptions options,
                                           const void *key,
                                           size_t keyLength,
                                           const void *iv,
                                           const void *dataIn,
                                           size_t dataInLength,
                                           void *dataOut,
                                           size_t dataOutAvailable,
                                           size_t *dataOutMoved);

static CCCryptorStatus replaced_CCCrypt(
                                        CCOperation op,
                                        CCAlgorithm alg,
                                        CCOptions options,
                                        const void *key,
                                        size_t keyLength,
                                        const void *iv,
                                        const void *dataIn,
                                        size_t dataInLength,
                                        void *dataOut,
                                        size_t dataOutAvailable,
                                        size_t *dataOutMoved)
{
    NSLog(@"CCryptCalled %u", alg);
    CCCryptorStatus origResult = original_CCCrypt(op, alg, options, key, keyLength, iv, dataIn,
                                                  dataInLength, dataOut, dataOutAvailable, dataOutMoved);
    
   
    return origResult;
}


static int (*original_open)(const char *path, int oflag, mode_t mode);
static FILE* (*original_fopen) ( const char * filename, const char * mode );


static void handleOpen(const char* path) {
    
    if(path != NULL) {
        
        NSString *pathString = [[NSString stringWithUTF8String:path] stringByResolvingSymlinksInPath];
        
        // Results are cached within the broker instance
        // and are delivered to the DiOS backend when app execution has finished
        if ([pathString hasSuffix:@".js"]) {
            NSLog(@"wow js loaded!");
            NSLog(@"%@",[NSThread callStackSymbols]);
        }
        
    }
    
}

static int replaced_open(const char *path, int oflag, mode_t mode) {
    
    handleOpen(path);
    //NSLog(@"Opening file %s", path);
    return original_open(path, oflag, mode);
}

static FILE* replaced_fopen(const char *filename, const char * mode) {
    
    handleOpen(filename);
      //NSLog(@"Opening file %s", filename);
    return original_fopen(filename, mode);
}





%ctor {
    NSLog(@"RELAH ACTIVATED!");
     MSHookFunction((void *) CCCrypt, (void *)  replaced_CCCrypt, (void **) &original_CCCrypt);
    MSHookFunction((void*)open, (void*)replaced_open, (void**)&original_open);
    MSHookFunction((void*)fopen, (void*)replaced_fopen, (void**)&original_fopen);
     MSHookFunction((void *) SecKeyEncrypt, (void *)  replaced_SecKeyEncrypt, (void **) &original_SecKeyEncrypt);
    
}

%hook UIWebView

- (NSString *)stringByEvaluatingJavaScriptFromString:(NSString *)script {
    NSLog(@"RELAH: JAVASCRIPT");
    NSLog(@"%@", script);
    return %orig;
}
%end
/*
%hook SecurityHelper

+ (id)md5DataFromString:(id)arg1 {
    NSLog(@"RELAH: md5DataFromString called %@", arg1);
    id result = %orig;
    NSLog(@"RELAH: md5DataFromString result %@", result);
    return result;

}
+ (id)doCipher:(id)arg1 key1:(id)arg2 key2:(id)arg3 operation:(unsigned int)arg4 {
    NSLog(@"RELAH: doCipher called arg1: %@, key1: %@, key2: %@", arg1, arg2, arg3);
    NSLog(@"DOCIPHER %@",[NSThread callStackSymbols]);
    id result = %orig;
    NSLog(@"RELAH: doCipher result %@", result);
    return @"";
    //return result;
}
+ (id)decrypt:(id)arg1 password:(id)arg2 {
    NSLog(@"RELAH: decrypt called, arg1: %@, password: %@", arg1, arg2);
    id result = %orig;
    NSLog(@"RELAH: decrypt result %@", result);
    return result;
}
+ (id)encrypt:(id)arg1 password:(id)arg2 {
    NSLog(@"RELAH: encrypt called, arg1: %@, password: %@", arg1, arg2);
    id result = %orig;
    NSLog(@"RELAH: encrypt result %@", result);
    return result;
}

- (id)genKEY1:(id)arg1 {
    NSLog(@"RELAH: genKey1 called: %@", arg1);
    id result = %orig;
    NSLog(@"RELAH: genKey1 result %@", result);
    return result;
}
- (id)getTimeStamp {
    NSLog(@"RELAH: getTimeStamp called");
    id result = %orig;
    NSLog(@"RELAH: getTimeStamp result %@", result);
    return result;
}
- (id)genKEY2 {
    NSLog(@"RELAH: genKey1 called");
    id result = %orig;
    NSLog(@"RELAH: genKey2 result %@", result);
    return result;
}
- (id)getUDIDTokenKey {
    NSLog(@"RELAH: getUDIDTokenKey Called");
    id result = %orig;
    NSLog(@"RELAH: getUDIDTokenKey result %@", result);
    return result;
}


- (int)charToNum:(id)arg1 {
    NSLog(@"RELAH: charToNum called: %@", arg1);
    int result = %orig;
    NSLog(@"RELAH: charToNum result %u", result);
    return result;
}
- (id)toCharArray:(id)arg1 {
    NSLog(@"RELAH: toCharArray called: %@", arg1);
    id result = %orig;
    NSLog(@"RELAH: toCharArray result %@", result);
    return result;
}

- (id)genSqlTokens:(id)arg1 decryptEncrypt:(_Bool)arg2 {
    NSLog(@"RELAH: genSqlTokens called: %@", arg1);
    id result = %orig;
    NSLog(@"RELAH: genSqlTokens result %@", result);
    return result;
}
- (id)genTokens {
    NSLog(@"RELAH: genTokens called");
    id result = %orig;
    NSLog(@"RELAH: genTokens result %@", result);
    return result;
    
}

%end*/

%hook base64compression

+ (id)base64forData:(id)arg1 {
    NSLog(@"RELAH: base64fordata called");
    return %orig;
}
+ (id)decodeStringFromKony:(id)arg1 {
    NSLog(@"RELAH: decodeStringFromKony called");
    return %orig;
    
}

%end


%hook NSData


- (id)HMACWithAlgorithm:(unsigned int)arg1 key:(id)arg2 {
    NSLog(@"RELAH: HMACWithAlgorithm called");
    return %orig;
}
- (id)HMACWithAlgorithm:(unsigned int)arg1 {
    NSLog(@"RELAH: HMACWithAlgoritmh2 called");
    return %orig;
}

- (id)decryptedCASTDataUsingKey:(id)arg1 error:(id *)arg2 {
    NSLog(@"RELAH: decryptedCASTDataUsingKey called");
    return %orig;
}
- (id)CASTEncryptedDataUsingKey:(id)arg1 error:(id *)arg2 {
    NSLog(@"RELAH: CASTEncryptedDataUsingKey called");
    return %orig;
}
- (id)decryptedDESDataUsingKey:(id)arg1 error:(id *)arg2 {
    NSLog(@"RELAH: decryptedDESDataUsingKey called");
    return %orig;
}
- (id)DESEncryptedDataUsingKey:(id)arg1 error:(id *)arg2 {
    NSLog(@"RELAH: DESEncryptedDataUsingKey called");
    return %orig;
}
- (id)decryptedAES256DataUsingKey:(id)arg1 error:(id *)arg2 {
    NSLog(@"RELAH: decryptedAES256DataUsingKey called");
    return %orig;
}
- (id)AES256EncryptedDataUsingKey:(id)arg1 error:(id *)arg2 {
    NSLog(@"RELAH: AES256EncryptedDataUsingKey called");
    return %orig;
}

    - (id)decryptedDataUsingAlgorithm:(unsigned int)arg1 key:(id)arg2 initializationVector:(id)arg3 options:(unsigned int)arg4 error:(int *)arg5 {
        NSLog(@"RELAH: decryptedDataUsingAlgortihm called");
        return %orig;
    }
    - (id)decryptedDataUsingAlgorithm:(unsigned int)arg1 key:(id)arg2 options:(unsigned int)arg3 error:(int *)arg {
        NSLog(@"RELAH: decryptedDataUsingAlgortihm2 called");
            return %orig;
    }
    - (id)decryptedDataUsingAlgorithm:(unsigned int)arg1 key:(id)arg2 error:(int *)arg3 {
        NSLog(@"RELAH: decryptedDataUsingAlgortihm3 called");
            return %orig;
    }
    - (id)dataEncryptedUsingAlgorithm:(unsigned int)arg1 key:(id)arg2 initializationVector:(id)arg3 options:(unsigned int)arg4 error:(int *)arg5 {
        NSLog(@"RELAH: dataEncryptedusingAlgorthm1 called");
        return %orig;
    }
    - (id)dataEncryptedUsingAlgorithm:(unsigned int)arg1 key:(id)arg2 options:(unsigned int)arg3 error:(int *)arg4 {
        NSLog(@"RELAH: dataEncryptedusingAlgorthm1 called");
        return %orig;
    }
    - (id)dataEncryptedUsingAlgorithm:(unsigned int)arg1 key:(id)arg2 error:(int *)arg3 {
        NSLog(@"RELAH: dataEncryptedusingAlgorthm1 called");
        return %orig;
    }
    - (id)_runCryptor:(struct _CCCryptor *)arg1 result:(int *)arg2 {
        NSLog(@"RELAH: dataEncryptedusingAlgorthm1 called");
        return %orig;
    }
%end

%hook AESCrypto


+ (id)decryptKeychainData:(id)arg1 key:(id)arg2 {
    NSLog(@"RELAH: decryptKeyChainData called");
    return %orig;
}
+ (id)decryptData:(id)arg1 randomString:(id)arg2 {
    NSLog(@"RELAH: AESCrypto-decryptData called arg1: %@, randomString %@", arg1, arg2);
    id result = %orig;
    NSLog(@"RELAH: AESCrypto-decryptData result %@", result);
    return result;
    
}
+ (id)encryptData:(id)arg1 randomString:(id)arg2 {
    NSLog(@"RELAH: AESCrypto-ENCRYPTData called arg1: %@, randomString %@", arg1, arg2);
    id result = %orig;
    NSLog(@"RELAH: AESCrypto-ENCRYPTData result %@", result);
    return result;
    
}

%end

%hook RSAEncryption

- (id)randomStringWithLength:(int)arg1 {
    NSLog(@"RELAH: randomStringWithLength called %u", arg1);
    // NSLog(@"%@",[NSThread callStackSymbols]);
    return %orig;
}
- (id)getRandomString {
    NSLog(@"RELAH: randomString called");
    // NSLog(@"%@",[NSThread callStackSymbols]);
    return %orig;
}
- (id)base64forData:(id)arg1 {
    NSLog(@"RELAH: base64ForData called %@", arg1);
    // NSLog(@"%@",[NSThread callStackSymbols]);
    id result = %orig;
    NSLog(@"RELAH: base64 result %@", result);
    return result;
    
}
- (id)encryptToString:(id)arg1 {
    NSLog(@"RELAH: encryptToString called %@", arg1);
    // NSLog(@"%@",[NSThread callStackSymbols]);
    return %orig;
}
- (id)encryptWithString:(id)arg1 {
    NSLog(@"RELAH: encryptWithString called %@", arg1);
    //NSLog(@"RELAH: %@",[NSThread callStackSymbols]);
      id result = %orig;
    NSLog(@"RELAH: encryptWithString result %@", result);
    return result;
 
}
- (id)encryptWithData:(id)arg1 {
    NSLog(@"RELAH: encryptWithData called %@", arg1);
     NSLog(@"%@",[NSThread callStackSymbols]);

    id result = %orig;
    NSLog(@"RELAH: encryptWithData result %@", result);
    return %orig;
}
- (id)initWithPublicKey:(id)arg1 {
    NSLog(@"RELAH: initWithPublicKey called %@", arg1);
    // NSLog(@"%@",[NSThread callStackSymbols]);
    return %orig;
    
}
- (id)initWithData:(id)arg1 {
    NSLog(@"initWithData called %@", arg1);
    NSData* data = (NSData*) arg1;
    NSLog(@"initWithData base64 %@", [data base64EncodedStringWithOptions:0]);
    NSLog(@"%@",[NSThread callStackSymbols]);
    return %orig;
    
}
// Always make sure you clean up after yourself; Not doing so could have grave consequences!
%end



%hook swiftPayLahScanQRCodeController
- (void)donePressed {
    NSLog(@"RELAH: DONE PRESSED");
    %orig;
}
- (void)updateCounterWithString:(id)arg1 {
    NSLog(@"RELAH: UPDATE COUNTER PRESSED %@", arg1);
    %orig;
}
-(id)setQrCode:(id)qrCode key:(id)arg2 {
    NSLog(@"setQR Code %@ : %@", qrCode, arg2);
    return %orig;
}
-(id)setNetsQRCode:(id)qrCode key:(id)arg2 {
    NSLog(@"setNetsQR Code %@ : %@", qrCode, arg2);
        return %orig;
}
-(id)setQrCodeScanner:(id)qrCode key:(id)arg2 {
    NSLog(@"setQrCodeScanner %@ : %@", qrCode, arg2);
        return %orig;
}
-(id)setQrCodeImagePicker:(id)qrCode key:(id)arg2  {
    NSLog(@"setQrCodeImagePicker %@ : %@", qrCode, arg2);
        return %orig;
}


/*
  @interface PayLah.PayLahQRCodeImagePicker (PayLah) <UIImagePickerControllerDelegate>
  - (void)invalidQRCodePicked;
  - (void)validQRCodePickedWithParsedQRCode:(id)arg1;
  - (void)imagePickerController:(id)arg1 didFinishPickingMediaWithInfo:(id)arg2;
  */
%hook swiftPayLahQRCodeImagePicker
- (void)imagePickerController:(id)arg1 didFinishPickingMediaWithInfo:(id)arg2 {
    NSLog(@"RELAH: FINISH PICKING IMAGE");
    %orig;
}
%end

%ctor {
    %init(swiftPayLahQRCodeImagePicker = objc_getClass("PayLah.PayLahQRCodeImagePicker"));
   // %init();
}
