#import "AppDelegate.h"
#import "ViewController.h"

@implementation AppDelegate

- (BOOL)application:(UIApplication *)application
    didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
  (void)application;
  (void)launchOptions;

  CGRect bounds = [[UIScreen mainScreen] bounds];
  self.window = [[UIWindow alloc] initWithFrame:bounds];
  self.window.rootViewController = [[ViewController alloc] init];
  [self.window makeKeyAndVisible];
  return YES;
}

- (void)applicationWillResignActive:(UIApplication *)application { (void)application; }
- (void)applicationDidEnterBackground:(UIApplication *)application { (void)application; }
- (void)applicationWillEnterForeground:(UIApplication *)application { (void)application; }
- (void)applicationDidBecomeActive:(UIApplication *)application { (void)application; }

@end