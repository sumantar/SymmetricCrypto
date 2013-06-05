//
//  ViewController.m
//  CryptoSample
//
//  Created by sumantar on 02/05/13.
//  Copyright (c) 2013 sumantar. All rights reserved.
//

#import "ViewController.h"
#import "SRSymmetricCrypto.h"


@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad
{
    [super viewDidLoad];
	// Do any additional setup after loading the view, typically from a nib.
    
    SRSymmetricCrypto *crypto = [[SRSymmetricCrypto alloc] init];
       
    NSString *encryptedData = [crypto symmetricEncryption:@"TMID String"];
    NSLog(@"encrypted data: %@", encryptedData);
    
    //Decrypt
    NSString *plainText = [crypto symmetricDecryption:encryptedData];
    NSLog(@"plain text data: %@", plainText);
}

- (void)didReceiveMemoryWarning
{
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

@end
