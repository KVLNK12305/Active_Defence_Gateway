#include <stdio.h>
#include <dlfcn.h>
int main() {
    void *handle = dlopen("/home/kushal/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/lib/libLLVM-22-rust-1.97.0-nightly.so", RTLD_NOW);
    if (!handle) {
        printf("dlopen error: %s\n", dlerror());
    } else {
        printf("Success\n");
    }
    return 0;
}
