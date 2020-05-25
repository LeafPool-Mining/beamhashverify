#include <nan.h>
#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include <stdint.h>
#include "crypto/equihashR.h"
#include "crypto/beamHashIII.h"
#include "beam/core/difficulty.h"
#include "beam/core/uintBig.h"

#include <sodium.h>

#include <vector>
using namespace v8;

int verifyBH(const char *hdr, const char *nonceBuffer, const std::vector<unsigned char> &soln, PoWScheme* BeamHash){
  blake2b_state m_Blake;
  BeamHash->InitialiseState(m_Blake);
  blake2b_update(&m_Blake, (const unsigned char *)hdr, 32);
  blake2b_update(&m_Blake, (const unsigned char *)nonceBuffer, 8);
  return BeamHash->IsValidSolution(m_Blake, soln);
}

void Verify(const v8::FunctionCallbackInfo<Value>& args) {
  Isolate* isolate = Isolate::GetCurrent();
  HandleScope scope(isolate);
  static BeamHash_III beamHashIII;
  unsigned int version = 3;

  if (args.Length() < 3) {
  isolate->ThrowException(Exception::TypeError(
    String::NewFromUtf8(isolate, "Wrong number of arguments")));
  return;
  }

  Local<Object> header = args[0]->ToObject();
  Local<Object> nonce = args[1]->ToObject();
  Local<Object> solution = args[2]->ToObject();

  if (args.Length() == 4) {
      version = args[3]->Uint32Value();
  }

  if(!node::Buffer::HasInstance(header) || !node::Buffer::HasInstance(solution) || !node::Buffer::HasInstance(nonce) ) {
  isolate->ThrowException(Exception::TypeError(
    String::NewFromUtf8(isolate, "Arguments should be buffer objects.")));
  return;
  }

  const char *hdr = node::Buffer::Data(header);
  const char *nonceBuffer = node::Buffer::Data(nonce);
  if(node::Buffer::Length(header) != 32) {
	  //invalid hdr length
	  args.GetReturnValue().Set(false);
	  return;
  }
  const char *soln = node::Buffer::Data(solution);

  std::vector<unsigned char> vecSolution(soln, soln + node::Buffer::Length(solution));
  
  PoWScheme* BeamHash;
  if ( version == 3 )
  {
    BeamHash = &beamHashIII;
  }
  if ( version == 2 )
  {
    BeamHash = &BeamHashII;
  }
  else if ( version == 1 )
  {
    BeamHash = &BeamHashI;
  }

  bool result = verifyBH(hdr, nonceBuffer, vecSolution, BeamHash);
  args.GetReturnValue().Set(result);

}

void VerifyDiff(const v8::FunctionCallbackInfo<Value> &args)
{
  Isolate *isolate = Isolate::GetCurrent();
  HandleScope scope(isolate);
  if (args.Length() < 2)
  {
    isolate->ThrowException(Exception::TypeError(
        String::NewFromUtf8(isolate, "Wrong number of arguments")));
    return;
  }
  unsigned int diff = 0;

  Local<Object> solution = args[0]->ToObject();
  if (!node::Buffer::HasInstance(solution))
  {
    isolate->ThrowException(Exception::TypeError(
        String::NewFromUtf8(isolate, "Argument should be buffer objects.")));
    return;
  }
  diff = args[1]->Uint32Value();

  const char *soln = node::Buffer::Data(solution);
  std::vector<unsigned char> vecSolution(soln, soln + node::Buffer::Length(solution));

  beam::Difficulty powDiff = beam::Difficulty(diff);
  beam::uintBig_t<32> hv;
  crypto_hash_sha256(hv.m_pData, vecSolution.data(), vecSolution.size());
  bool result = powDiff.IsTargetReached(hv);
  args.GetReturnValue().Set(result);
}

void Init(Handle<Object> exports)
{
  NODE_SET_METHOD(exports, "verify", Verify);
  NODE_SET_METHOD(exports, "verifyDiff", VerifyDiff);
}

NODE_MODULE(beamhashverify, Init)
