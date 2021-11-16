#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include <stdint.h>

extern "C" {
    #include "algorithms/bcrypt.h"
    #include "algorithms/blake.h"
    #include "algorithms/blake2s.h"
    #include "algorithms/c11.h"
    #include "algorithms/fresh.h"
    #include "algorithms/fugue.h"
    #include "algorithms/gost.h"
    #include "algorithms/gr.h"
    #include "algorithms/groestl.h"
    #include "algorithms/hefty1.h"
    #include "algorithms/keccak.h"
    #include "algorithms/lbry.h"
    #include "algorithms/minotaur.h"
    #include "algorithms/nist5.h"
    #include "algorithms/phi1612.h"
    #include "algorithms/quark.h"
    #include "algorithms/qubit.h"
    #include "algorithms/scryptn.h"
    #include "algorithms/sha256d.h"
    #include "algorithms/shavite3.h"
    #include "algorithms/skein.h"
    #include "algorithms/tribus.h"
    #include "algorithms/x11.h"
    #include "algorithms/x13.h"
    #include "algorithms/x15.h"
    #include "algorithms/x16r.h"
}

using namespace node;
using namespace v8;

#if NODE_MAJOR_VERSION >= 4

#define DECLARE_INIT(x) \
    void x(Local<Object> exports)

#define DECLARE_FUNC(x) \
    void x(const FunctionCallbackInfo<Value>& args)

#define DECLARE_SCOPE \
    v8::Isolate* isolate = args.GetIsolate();

#define SET_BUFFER_RETURN(x, len) \
    args.GetReturnValue().Set(Buffer::Copy(isolate, x, len).ToLocalChecked());

#define SET_BOOLEAN_RETURN(x) \
    args.GetReturnValue().Set(Boolean::New(isolate, x));

#define RETURN_EXCEPT(msg) \
    do { \
        Local<String> localResult; \
        MaybeLocal<String> result = String::NewFromUtf8(isolate, msg); \
        result.ToLocal(&localResult); \
        isolate->ThrowException(Exception::Error(localResult)); \
        return; \
    } while (0)

#else

#define DECLARE_INIT(x) \
    void x(Handle<Object> exports)

#define DECLARE_FUNC(x) \
    Handle<Value> x(const Arguments& args)

#define DECLARE_SCOPE \
    HandleScope scope

#define SET_BUFFER_RETURN(x, len) \
    do { \
        Buffer* buff = Buffer::New(x, len); \
        return scope.Close(buff->handle_); \
    } while (0)

#define SET_BOOLEAN_RETURN(x) \
    return scope.Close(Boolean::New(x));

#define RETURN_EXCEPT(msg) \
    const v8::Local<String> result = String::New(msg); \
    return ThrowException(Exception::Error(result));

#endif // NODE_MAJOR_VERSION

#if NODE_MAJOR_VERSION >= 12

#define DECLARE_CALLBACK(name, hash, output_len) \
    DECLARE_FUNC(name) { \
    DECLARE_SCOPE; \
 \
    if (args.Length() < 1) \
        RETURN_EXCEPT("You must provide one argument."); \
 \
    Local<Object> localTarget; \
    Local<Context> context = isolate->GetCurrentContext(); \
    MaybeLocal<Object> target = args[0]->ToObject(context); \
    target.ToLocal(&localTarget); \
 \
    if(!Buffer::HasInstance(localTarget)) \
        RETURN_EXCEPT("Argument should be a buffer object."); \
 \
    char * input = Buffer::Data(localTarget); \
    char output[output_len]; \
 \
    uint32_t input_len = Buffer::Length(localTarget); \
 \
    hash(input, output, input_len); \
 \
    SET_BUFFER_RETURN(output, output_len); \
}

#define DECLARE_NO_INPUT_LENGTH_CALLBACK(name, hash, output_len) \
    DECLARE_FUNC(name) { \
    DECLARE_SCOPE; \
 \
    if (args.Length() < 1) \
        RETURN_EXCEPT("You must provide one argument."); \
 \
    Local<Object> localTarget; \
    Local<Context> context = isolate->GetCurrentContext(); \
    MaybeLocal<Object> target = args[0]->ToObject(context); \
    target.ToLocal(&localTarget); \
 \
    if(!Buffer::HasInstance(localTarget)) \
        RETURN_EXCEPT("Argument should be a buffer object."); \
 \
    char * input = Buffer::Data(localTarget); \
    char output[output_len]; \
 \
    hash(input, output); \
 \
    SET_BUFFER_RETURN(output, output_len); \
}

#else

#define DECLARE_CALLBACK(name, hash, output_len) \
    DECLARE_FUNC(name) { \
    DECLARE_SCOPE; \
 \
    if (args.Length() < 1) \
        RETURN_EXCEPT("You must provide one argument."); \
 \
    Local<Object> localTarget = args[0]->ToObject(); \
 \
    if(!Buffer::HasInstance(localTarget)) \
        RETURN_EXCEPT("Argument should be a buffer object."); \
 \
    char * input = Buffer::Data(localTarget); \
    char output[output_len]; \
 \
    uint32_t input_len = Buffer::Length(localTarget); \
 \
    hash(input, output, input_len); \
 \
    SET_BUFFER_RETURN(output, output_len); \
}

#define DECLARE_NO_INPUT_LENGTH_CALLBACK(name, hash, output_len) \
    DECLARE_FUNC(name) { \
    DECLARE_SCOPE; \
 \
    if (args.Length() < 1) \
        RETURN_EXCEPT("You must provide one argument."); \
 \
    Local<Object> localTarget = args[0]->ToObject(); \
 \
    if(!Buffer::HasInstance(localTarget)) \
        RETURN_EXCEPT("Argument should be a buffer object."); \
 \
    char * input = Buffer::Data(localTarget); \
    char output[output_len]; \
 \
    hash(input, output); \
 \
    SET_BUFFER_RETURN(output, output_len); \
}

#endif // NODE_MAJOR_VERSION >= 12

DECLARE_CALLBACK(blake, blake_hash, 32);
DECLARE_CALLBACK(blake2s, blake2s_hash, 32);
DECLARE_CALLBACK(c11, c11_hash, 32);
DECLARE_CALLBACK(fresh, fresh_hash, 32);
DECLARE_CALLBACK(fugue, fugue_hash, 32);
DECLARE_CALLBACK(gost, gost_hash, 32);
DECLARE_CALLBACK(groestl, groestl_hash, 32);
DECLARE_CALLBACK(groestlmyriad, groestlmyriad_hash, 32);
DECLARE_CALLBACK(hefty1, hefty1_hash, 32);
DECLARE_CALLBACK(keccak, keccak_hash, 32);
DECLARE_CALLBACK(lbry, lbry_hash, 32);
DECLARE_CALLBACK(minotaur, minotaur_hash, 32);
DECLARE_CALLBACK(nist5, nist5_hash, 32);
DECLARE_CALLBACK(quark, quark_hash, 32);
DECLARE_CALLBACK(qubit, qubit_hash, 32);
DECLARE_CALLBACK(sha256d, sha256d_hash, 32);
DECLARE_CALLBACK(shavite3, shavite3_hash, 32);
DECLARE_CALLBACK(skein, skein_hash, 32);
DECLARE_CALLBACK(x11, x11_hash, 32);
DECLARE_CALLBACK(x13, x13_hash, 32);
DECLARE_CALLBACK(x15, x15_hash, 32);
DECLARE_CALLBACK(x16r, x16r_hash, 32);
DECLARE_CALLBACK(x16rv2, x16rv2_hash, 32);

DECLARE_NO_INPUT_LENGTH_CALLBACK(bcrypt, bcrypt_hash, 32);
DECLARE_NO_INPUT_LENGTH_CALLBACK(phi1612, phi1612_hash, 32);
DECLARE_NO_INPUT_LENGTH_CALLBACK(tribus, tribus_hash, 32);

DECLARE_FUNC(scrypt) {
    DECLARE_SCOPE;

    if (args.Length() < 3)
        RETURN_EXCEPT("You must provide buffer to hash, N value, and R value");

    #if NODE_MAJOR_VERSION >= 12
        Local<Object> localTarget;
        Local<Context> context = isolate->GetCurrentContext();
        MaybeLocal<Object> target = args[0]->ToObject(context);
        target.ToLocal(&localTarget);
    #else
        Local<Object> localTarget = args[0]->ToObject();
    #endif

    if(!Buffer::HasInstance(localTarget))
        RETURN_EXCEPT("Argument should be a buffer object.");

    #if NODE_MAJOR_VERSION >= 12
       Local<Context> currentContext = isolate->GetCurrentContext();
       unsigned int nValue = args[1]->Uint32Value(currentContext).FromJust();
       unsigned int rValue = args[2]->Uint32Value(currentContext).FromJust();
    #else
       unsigned int nValue = args[1]->Uint32Value();
       unsigned int rValue = args[2]->Uint32Value();
    #endif
       char * input = Buffer::Data(localTarget);
       char output[32];

    uint32_t input_len = Buffer::Length(localTarget);
    scrypt_N_R_1_256(input, output, nValue, rValue, input_len);
    SET_BUFFER_RETURN(output, 32);
}

DECLARE_FUNC(scryptn) {
    DECLARE_SCOPE;

    if (args.Length() < 2)
        RETURN_EXCEPT("You must provide buffer to hash and N factor.");

    #if NODE_MAJOR_VERSION >= 12
        Local<Object> localTarget;
        Local<Context> context = isolate->GetCurrentContext();
        MaybeLocal<Object> target = args[0]->ToObject(context);
        target.ToLocal(&localTarget);
    #else
        Local<Object> localTarget = args[0]->ToObject();
    #endif

    if(!Buffer::HasInstance(localTarget))
        RETURN_EXCEPT("Argument should be a buffer object.");

    #if NODE_MAJOR_VERSION >= 12
        Local<Context> currentContext = isolate->GetCurrentContext();
        unsigned int nFactor = args[1]->Uint32Value(currentContext).FromJust();
    #else
        unsigned int nFactor = args[1]->Uint32Value();
    #endif

    char output[32];
    char * input = Buffer::Data(localTarget);
    uint32_t input_len = Buffer::Length(localTarget);
    unsigned int N = 1 << nFactor;

    scrypt_N_R_1_256(input, output, N, 1, input_len);
    SET_BUFFER_RETURN(output, 32);
}

DECLARE_INIT(init) {
    NODE_SET_METHOD(exports, "bcrypt", bcrypt);
    NODE_SET_METHOD(exports, "blake", blake);
    NODE_SET_METHOD(exports, "blake2s", blake2s);
    NODE_SET_METHOD(exports, "c11", c11);
    NODE_SET_METHOD(exports, "fresh", fresh);
    NODE_SET_METHOD(exports, "fugue", fugue);
    NODE_SET_METHOD(exports, "gost", gost);
    NODE_SET_METHOD(exports, "groestl", groestl);
    NODE_SET_METHOD(exports, "groestlmyriad", groestlmyriad);
    NODE_SET_METHOD(exports, "hefty1", hefty1);
    NODE_SET_METHOD(exports, "keccak", keccak);
    NODE_SET_METHOD(exports, "lbry", lbry);
    NODE_SET_METHOD(exports, "minotaur", minotaur);
    NODE_SET_METHOD(exports, "nist5", nist5);
    NODE_SET_METHOD(exports, "phi1612", phi1612);
    NODE_SET_METHOD(exports, "quark", quark);
    NODE_SET_METHOD(exports, "qubit", qubit);
    NODE_SET_METHOD(exports, "scrypt", scrypt);
    NODE_SET_METHOD(exports, "scryptn", scryptn);
    NODE_SET_METHOD(exports, "sha256d", sha256d);
    NODE_SET_METHOD(exports, "shavite3", shavite3);
    NODE_SET_METHOD(exports, "skein", skein);
    NODE_SET_METHOD(exports, "tribus", tribus);
    NODE_SET_METHOD(exports, "x11", x11);
    NODE_SET_METHOD(exports, "x13", x13);
    NODE_SET_METHOD(exports, "x15", x15);
    NODE_SET_METHOD(exports, "x16r", x16r);
    NODE_SET_METHOD(exports, "x16rv2", x16rv2);
}

NODE_MODULE(multihashing, init)
