#ifndef CODEBULL_H
#define CODEBULL_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__GNUC__) || defined(__clang__)
#define SHADOW_API __attribute__((visibility("default")))
#else
#define SHADOW_API
#endif



SHADOW_API int enableShadowFunction(uint64_t fromAddr, uint64_t toAddr);








SHADOW_API int CopyFunction(void* start, void* end, void* funcBytes, size_t funcSize, void** outNewAddr, size_t* outSize, void* collectAddrs, size_t collectCount, void* collectorAddr, size_t* outPrologueShift);



SHADOW_API void reportShadowStartup(const char* version);

#ifdef __cplusplus
}
#endif

#endif 
