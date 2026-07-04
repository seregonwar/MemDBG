#import <UIKit/UIKit.h>
#import <Metal/Metal.h>
#import <MetalKit/MetalKit.h>

@interface ViewController : UIViewController <MTKViewDelegate>
@property (strong, nonatomic) MTKView *mtkView;
@property (strong, nonatomic) id<MTLDevice> device;
@property (strong, nonatomic) id<MTLCommandQueue> commandQueue;
@end