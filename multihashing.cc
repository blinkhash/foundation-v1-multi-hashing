#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include <stdint.h>

extern "C" {
    #include "allium.h"
    #include "bcrypt.h"
    #include "blake.h"
    #include "blake2s.h"
    #include "c11.h"
    #include "cryptonight.h"
    #include "cryptonight_fast.h"
    #include "fresh.h"
    #include "fugue.h"
    #include "gost.h"
    #include "groestl.h"
    #include "hefty1.h"
    #include "keccak.h"
    #include "lbry.h"
    #include "Lyra2.h"
    #include "Lyra2RE.h"
    #include "Lyra2REV2.h"
    #include "Lyra2REV3.h"
    #include "Lyra2Z.h"
    #include "lyra2z16m330.h"
    #include "lyra2z330.h"
    #include "minotaur.h"
    #include "neoscrypt.h"
    #include "nist5.h"
    #include "phi1612.h"
    #include "quark.h"
    #include "qubit.h"
    #include "scryptn.h"
    #include "sha256d.h"
    #include "shavite3.h"
    #include "skein.h"
    #include "tribus.h"
    #include "x11.h"
    #include "x13.h"
    #include "x15.h"
    #include "x16r.h"
    #include "x17.h"
    #include "yescrypt/yescrypt.h"
    #include "yescrypt/sha256_Y.h"
}

#include "boolberry.h"
#include "odo.h"

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
DECLARE_CALLBACK(lyra2z16m330, lyra2z16m330_hash, 32);
DECLARE_CALLBACK(lyra2z330, lyra2z330_hash, 32);
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
DECLARE_CALLBACK(x17, x17_hash, 32);

DECLARE_NO_INPUT_LENGTH_CALLBACK(allium, allium_hash, 32);
DECLARE_NO_INPUT_LENGTH_CALLBACK(bcrypt, bcrypt_hash, 32);
DECLARE_NO_INPUT_LENGTH_CALLBACK(lyra2re2, lyra2re2_hash, 32);
DECLARE_NO_INPUT_LENGTH_CALLBACK(lyra2rev2, lyra2rev2_hash, 32);
DECLARE_NO_INPUT_LENGTH_CALLBACK(lyra2rev3, lyra2rev3_hash, 32);
DECLARE_NO_INPUT_LENGTH_CALLBACK(lyra2z, lyra2z_hash, 32);
DECLARE_NO_INPUT_LENGTH_CALLBACK(phi1612, phi1612_hash, 32);
DECLARE_NO_INPUT_LENGTH_CALLBACK(tribus, tribus_hash, 32);
DECLARE_NO_INPUT_LENGTH_CALLBACK(yescrypt, yescrypt_hash, 32);

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

DECLARE_FUNC(neoscrypt) {
    DECLARE_SCOPE;

    if (args.Length() < 2)
        RETURN_EXCEPT("You must provide two arguments.");

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

    char output[32];
    char * input = Buffer::Data(localTarget);
    neoscrypt(input, output, 0);
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

DECLARE_FUNC(cryptonight) {
    DECLARE_SCOPE;

    #if NODE_MAJOR_VERSION >= 12
        Local<Context> currentContext = isolate->GetCurrentContext();
    #endif

    bool fast = false;
    uint32_t cn_variant = 0;
    uint64_t height = 0;

    if (args.Length() < 1)
        RETURN_EXCEPT("You must provide one argument.");

    if (args.Length() >= 2) {
        if(args[1]->IsBoolean())
            #if NODE_MAJOR_VERSION >= 12
                fast = args[1]->BooleanValue(isolate);
            #else
                fast = args[1]->BooleanValue();
            #endif
        else if(args[1]->IsUint32())
            #if NODE_MAJOR_VERSION >= 12
                cn_variant = args[1]->Uint32Value(currentContext).FromJust();
            #else
                cn_variant = args[1]->Uint32Value();
            #endif
        else
            RETURN_EXCEPT("Argument 2 should be a boolean or uint32_t");
    }

    if ((cn_variant == 4) && (args.Length() < 3)) {
        RETURN_EXCEPT("You must provide Argument 3 (block height) for Cryptonight variant 4");
    }

    if (args.Length() >= 3) {
        if(args[2]->IsUint32())
            #if NODE_MAJOR_VERSION >= 12
                height = args[2]->Uint32Value(currentContext).FromJust();
            #else
                height = args[2]->Uint32Value();
            #endif
        else
            RETURN_EXCEPT("Argument 3 should be uint32_t");
    }

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

    char output[32];
    char * input = Buffer::Data(localTarget);
    uint32_t input_len = Buffer::Length(localTarget);

    if(fast)
        cryptonight_fast_hash(input, output, input_len);
    else {
        if ((cn_variant == 1) && input_len < 43)
            RETURN_EXCEPT("Argument must be 43 bytes for monero variant 1");
        cryptonight_hash(input, output, input_len, cn_variant, height);
    }
    SET_BUFFER_RETURN(output, 32);
}

DECLARE_FUNC(cryptonightfast) {
    DECLARE_SCOPE;

    #if NODE_MAJOR_VERSION >= 12
        Local<Context> currentContext = isolate->GetCurrentContext();
    #endif

    bool fast = false;
    uint32_t cn_variant = 0;

    if (args.Length() < 1)
        RETURN_EXCEPT("You must provide one argument.");

    if (args.Length() >= 2) {
        if(args[1]->IsBoolean())
            #if NODE_MAJOR_VERSION >= 12
                fast = args[1]->BooleanValue(isolate);
            #else
                fast = args[1]->BooleanValue();
            #endif
        else if(args[1]->IsUint32())
            #if NODE_MAJOR_VERSION >= 12
                cn_variant = args[1]->Uint32Value(currentContext).FromJust();
            #else
                cn_variant = args[1]->Uint32Value();
            #endif
        else
            RETURN_EXCEPT("Argument 2 should be a boolean or uint32_t");
    }

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

    char output[32];
    char * input = Buffer::Data(localTarget);
    uint32_t input_len = Buffer::Length(localTarget);

    if(fast)
        cryptonightfast_fast_hash(input, output, input_len);
    else {
        if (cn_variant > 0 && input_len < 43)
            RETURN_EXCEPT("Argument must be 43 bytes for monero variant 1+");
        cryptonightfast_hash(input, output, input_len, cn_variant);
    }
    SET_BUFFER_RETURN(output, 32);
}

DECLARE_FUNC(boolberry) {
    DECLARE_SCOPE;

    #if NODE_MAJOR_VERSION >= 12
        Local<Context> currentContext = isolate->GetCurrentContext();
    #endif

    if (args.Length() < 2)
        RETURN_EXCEPT("You must provide two arguments.");

    #if NODE_MAJOR_VERSION >= 12
        Local<Object> localTarget;
        Local<Object> localTarget_spad;
        Local<Context> context = isolate->GetCurrentContext();
        MaybeLocal<Object> target = args[0]->ToObject(context);
        MaybeLocal<Object> target_spad = args[1]->ToObject(context);
        target.ToLocal(&localTarget);
        target_spad.ToLocal(&localTarget_spad);
    #else
        Local<Object> localTarget = args[0]->ToObject();
        Local<Object> localTarget_spad = args[1]->ToObject();
    #endif

    if(!Buffer::HasInstance(localTarget))
        RETURN_EXCEPT("Argument 1 should be a buffer object.");

    if(!Buffer::HasInstance(localTarget_spad))
        RETURN_EXCEPT("Argument 2 should be a buffer object.");

    uint32_t height = 1;
    if(args.Length() >= 3) {
        if(args[2]->IsUint32())
            #if NODE_MAJOR_VERSION >= 12
                height = args[2]->Uint32Value(currentContext).FromJust();
            #else
                height = args[2]->Uint32Value();
            #endif
        else
            RETURN_EXCEPT("Argument 3 should be an unsigned integer.");
    }

    char output[32];
    char * input = Buffer::Data(localTarget);
    char * scratchpad = Buffer::Data(localTarget_spad);

    uint32_t input_len = Buffer::Length(localTarget);
    uint64_t spad_len = Buffer::Length(localTarget_spad);
    boolberry_hash(input, input_len, scratchpad, spad_len, output, height);
    SET_BUFFER_RETURN(output, 32);
}

DECLARE_FUNC(odo) {
    DECLARE_SCOPE;

    if (args.Length() < 2)
        RETURN_EXCEPT("You must provide buffer to hash and key value");

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
        unsigned int keyValue = args[1]->Uint32Value(currentContext).FromJust();
    #else
        unsigned int keyValue = args[1]->Uint32Value();
    #endif

    char output[32];
    char * input = Buffer::Data(localTarget);
    uint32_t input_len = Buffer::Length(localTarget);

    odo_hash(input, output, input_len, keyValue);
    SET_BUFFER_RETURN(output, 32);
}

DECLARE_INIT(init) {
    NODE_SET_METHOD(exports, "allium", allium);
    NODE_SET_METHOD(exports, "bcrypt", bcrypt);
    NODE_SET_METHOD(exports, "blake", blake);
    NODE_SET_METHOD(exports, "blake2s", blake2s);
    NODE_SET_METHOD(exports, "boolberry", boolberry);
    NODE_SET_METHOD(exports, "c11", c11);
    NODE_SET_METHOD(exports, "cryptonight", cryptonight);
    NODE_SET_METHOD(exports, "cryptonightfast", cryptonightfast);
    NODE_SET_METHOD(exports, "fresh", fresh);
    NODE_SET_METHOD(exports, "fugue", fugue);
    NODE_SET_METHOD(exports, "gost", gost);
    NODE_SET_METHOD(exports, "groestl", groestl);
    NODE_SET_METHOD(exports, "groestlmyriad", groestlmyriad);
    NODE_SET_METHOD(exports, "hefty1", hefty1);
    NODE_SET_METHOD(exports, "keccak", keccak);
    NODE_SET_METHOD(exports, "lbry", lbry);
    NODE_SET_METHOD(exports, "lyra2re2", lyra2re2);
    NODE_SET_METHOD(exports, "lyra2rev2", lyra2rev2);
    NODE_SET_METHOD(exports, "lyra2rev3", lyra2rev3);
    NODE_SET_METHOD(exports, "lyra2z", lyra2z);
    NODE_SET_METHOD(exports, "lyra2z16m330", lyra2z16m330);
    NODE_SET_METHOD(exports, "lyra2z330", lyra2z330);
    NODE_SET_METHOD(exports, "minotaur", minotaur);
    NODE_SET_METHOD(exports, "neoscrypt", neoscrypt);
    NODE_SET_METHOD(exports, "nist5", nist5);
    NODE_SET_METHOD(exports, "odo", odo);
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
    NODE_SET_METHOD(exports, "x17", x17);
    NODE_SET_METHOD(exports, "yescrypt", yescrypt);
}

NODE_MODULE(multihashing, init)
