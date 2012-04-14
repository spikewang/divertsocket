#include <SystemConfiguration/SystemConfiguration.h>
#include <Cocoa/Cocoa.h>

char hostname[400];

@interface AddressResolution: NSObject
- (char *) getAddressOfPrimaryInterface;
@end


@implementation AddressResolution
- (char *) getAddressOfPrimaryInterface
{
	NSAutoreleasePool * pool = [[NSAutoreleasePool alloc] init];
	int i;

	SCDynamicStoreContext context = { 0, (void *)self, NULL, NULL, NULL };

	SCDynamicStoreRef dynStore = SCDynamicStoreCreate(
					NULL,
					(CFStringRef) [[NSBundle mainBundle] bundleIdentifier],
					nil,
					&context);

	NSArray * allKeys;
		
	NSString * primaryInterface;

	allKeys = [(NSArray *)SCDynamicStoreCopyKeyList(dynStore, CFSTR("State:/Network/Global/IPv4")) autorelease];

	for ( i = 0; i < [allKeys count]; i++ ) {
		NSLog(@"Current key: %@, value: %@",
			[allKeys objectAtIndex:i],
			[(NSString *)SCDynamicStoreCopyValue(dynStore, (CFStringRef)[allKeys objectAtIndex:i]) autorelease]);

		NSDictionary * dict = [(NSDictionary *)
								  SCDynamicStoreCopyValue(dynStore, (CFStringRef)[allKeys objectAtIndex:i]) autorelease];

		NSLog(@"PrimaryInterface: %@ value is: %@", [allKeys objectAtIndex:i], [dict objectForKey:@"PrimaryInterface"]);

		primaryInterface = (NSString *) [dict objectForKey:@"PrimaryInterface"];
	}
	
	allKeys = [(NSArray *)SCDynamicStoreCopyKeyList(dynStore,
													CFStringCreateWithFormat(kCFAllocatorDefault,
																			 NULL,
																			 CFSTR("State:/Network/Interface/%@/IPv4"),
																			 primaryInterface)) autorelease];
	for ( i = 0; i < [allKeys count]; i++ ) {
		NSLog(@"Current key: %@, value: %@",
			  [allKeys objectAtIndex:i],
			  [(NSString *)SCDynamicStoreCopyValue(dynStore, (CFStringRef)[allKeys objectAtIndex:i]) autorelease]);
		
		NSDictionary * dict = [(NSDictionary *)
									  SCDynamicStoreCopyValue(dynStore, (CFStringRef)[allKeys objectAtIndex:i]) autorelease];

		NSLog(@"IPv4 interface: %@ value is: %@", [allKeys objectAtIndex:i], [dict objectForKey:@"Addresses"]);

		strcpy(hostname, [[[dict objectForKey:@"Addresses"] objectAtIndex:0] cString]);
	}

	[pool release];

	return hostname;
}
@end


/**
 * @brief return the ip address of the primary interface
 *
 * This will return the ip address of the primary interface of system as a 
 * string
 */
char * getPrimaryAddress()
{
	AddressResolution *m = [[AddressResolution alloc] init];

	return [m getAddressOfPrimaryInterface];
}















