/******************************************************************************
* Copyright (c) 2000-2019 Ericsson Telecom AB
* All rights reserved. This program and the accompanying materials
* are made available under the terms of the Eclipse Public License v2.0
* which accompanies this distribution, and is available at
* https://www.eclipse.org/org/documents/epl-2.0/EPL-2.0.html
*
* Contributors:
* Timea Moder
* Endre Kulcsar
* Tibor Bende
* Gabor Szalai
******************************************************************************/
//
//  File:               EAP_EncDec.cc
//  Description:        Encoder/Decoder and external functions for EAP
//  Rev:                R2A
//  Prodnr:             CNL 113 599
//  Reference:          RFC 3748 PPP Extensible Authentication Protocol (EAP)
//                      Obsolate: RFC 2284
//                      draft-haverinen-pppext-eap-sim-16.txt                       
//                      draft-arkko-pppext-eap-aka-15.txt
//                       

#include "EAP_Types.hh"

#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/hmac.h>
#include <openssl/aes.h>

namespace EAP__Types{


void f__set__Ki(const INTEGER& identifier, const OCTETSTRING& value, EAP__port__descriptor& descriptor) {
  int id = identifier;
  if ((id < 0) || (id > 256)) TTCN_error ("Invalid identifier %d setting K value",id);
  if(tsp__global__keying){descriptor.Ki()[256]=value;}
  else{descriptor.Ki()[id] = value;}
} // set_K

void f__set__K(const INTEGER& identifier, const OCTETSTRING& value, EAP__port__descriptor& descriptor) {
  int id = identifier;
  if ((id < 0) || (id > 256)) TTCN_error ("Invalid identifier %d setting K value",id);
  if(tsp__global__keying){descriptor.K()[256]=value;}
  else{descriptor.K()[id] = value;}
} // set_K

void f__set__SQN(const INTEGER& identifier, const OCTETSTRING& value,EAP__port__descriptor& descriptor) {
  int id = identifier;
  if ((id < 0) || (id > 256)) TTCN_error ("Invalid identifier %d setting SQN value",id);
  if(tsp__global__keying){descriptor.SQN()[256]=value;}
  else{descriptor.SQN()[id] = value;}
} // set_SQN

void f__set__SQN__MS(const INTEGER& identifier, const OCTETSTRING& value,EAP__port__descriptor& descriptor) {
  int id = identifier;
  if ((id < 0) || (id > 256)) TTCN_error ("Invalid identifier %d setting SQN_MS value",id);
  if(tsp__global__keying){descriptor.SQN__MS()[256]=value;}
  else{descriptor.SQN__MS()[id] = value;}
} // set_SQN_MS

void f__set__AMF(const INTEGER& identifier, const OCTETSTRING& value,EAP__port__descriptor& descriptor) {
  int id = identifier;
  if ((id < 0) || (id > 256)) TTCN_error ("Invalid identifier %d setting AMF value",id);
  if(tsp__global__keying){descriptor.AMF()[256]=value;}
  else{descriptor.AMF()[id] = value;}
} // set_AMF

OCTETSTRING f__calc__HMAC(const OCTETSTRING& pl_key,const OCTETSTRING& input,const INTEGER& pl_length)
   {  
      unsigned int out_length;
      unsigned char output[out_length];     
      HMAC(EVP_sha1(),pl_key,(size_t) pl_key.lengthof(),input,(size_t) input.lengthof(),output,&out_length);
      OCTETSTRING HMAC_Value(pl_length,output);  
            
      return HMAC_Value;   
   }
/*   
OCTETSTRING f__calc__SHA1(const OCTETSTRING& input,const INTEGER& pl_length)
   {  
      unsigned int out_length=pl_length;
      unsigned char output[out_length];     
      SHA1(input,(size_t) input.lengthof(),output);  
      OCTETSTRING SHA_Value(out_length,output);  
            
      return SHA_Value;   
   }*/

OCTETSTRING f__encrypt__at__encr(const OCTETSTRING& key,const OCTETSTRING& input,const OCTETSTRING& ivec,const BOOLEAN& decrypt)
{
  unsigned char t_ivec[16];
  memcpy (t_ivec, (const unsigned char*)ivec, 16);
  AES_KEY aes_key;
  unsigned char output[65535];
  OCTETSTRING crypted;
  if (decrypt)
  {
    if(AES_set_decrypt_key((const unsigned char*)(key), 128, &aes_key))
      TTCN_warning("Wrong Kencr given to AES_set_decrypt_key()");
    AES_cbc_encrypt(input, output, input.lengthof(), &aes_key,t_ivec, AES_DECRYPT);
    crypted=OCTETSTRING(input.lengthof(),output);
  }
  else
  {
    if(AES_set_encrypt_key((const unsigned char*)(key), 128, &aes_key))
      TTCN_warning("Wrong Kencr given to AES_set_encrypt_key()");
    AES_cbc_encrypt(input,output, input.lengthof(),  &aes_key,t_ivec, AES_ENCRYPT);
    crypted=OCTETSTRING(input.lengthof(),output);
  }
  return crypted;
}

at__sim__encr__data f__crypt__atSimEncrData(const at__sim__encr__data& pl_encr_data,const OCTETSTRING& key,const OCTETSTRING& ivec,const BOOLEAN& decrypt)
{
  at__sim__encr__data ret_val;
  ret_val.attrib() = pl_encr_data.attrib();
  ret_val.attrib__length()=pl_encr_data.attrib__length();
  ret_val.reserved()=pl_encr_data.reserved();
  if(decrypt)//(pl_encr_data.attrib__value().get_selection()==at__sim__nested::ALT_encrypted__attrib__value)
  {
    OCTETSTRING temp = f__encrypt__at__encr(key,pl_encr_data.attrib__value().encrypted__attrib__value(),ivec,true);
    TTCN_Buffer buf;
    TTCN_EncDec::error_type_t err;
    buf.clear();
    TTCN_EncDec::clear_error();
    TTCN_EncDec::set_error_behavior(TTCN_EncDec::ET_ALL, TTCN_EncDec::EB_WARNING);
    buf.put_os(temp);
    eap__sim__attrib__list vl_attrib_list;
    vl_attrib_list.decode(eap__sim__attrib__list_descr_, buf, TTCN_EncDec::CT_RAW );
    err = TTCN_EncDec::get_last_error_type();
    if(err != TTCN_EncDec::ET_NONE)
      TTCN_warning("Decoding error: %s\n", TTCN_EncDec::get_error_str());
    ret_val.attrib__value().decrypted__attrib__value()=vl_attrib_list;
  }
  else//(pl_encr_data.attrib__value().get_selection()==at__sim__nested::ALT_decrypted__attrib__value)
  {
    TTCN_Buffer buf;
    TTCN_EncDec::error_type_t err;
    buf.clear();
    TTCN_EncDec::clear_error();
    TTCN_EncDec::set_error_behavior(TTCN_EncDec::ET_ALL, TTCN_EncDec::EB_WARNING);
    OCTETSTRING temp;
    if(pl_encr_data.attrib__value().get_selection()==at__sim__nested::ALT_decrypted__attrib__value)
    {
      pl_encr_data.attrib__value().decrypted__attrib__value().encode(eap__sim__attrib__list_descr_, buf, TTCN_EncDec::CT_RAW);
      err = TTCN_EncDec::get_last_error_type();
      if(err != TTCN_EncDec::ET_NONE)
        TTCN_warning("Encoding error: %s\n", TTCN_EncDec::get_error_str());
      temp=OCTETSTRING(buf.get_len(), buf.get_data());
    }
    else
    {
      temp=OCTETSTRING(pl_encr_data.attrib__value().encrypted__attrib__value().lengthof(),pl_encr_data.attrib__value().encrypted__attrib__value());
    }
    if ((temp.lengthof() %16) != 0)
    {
      int length = (temp.lengthof() % 16);
      temp=temp+OCTETSTRING(1, (const unsigned char*)"\6")+int2oct(((16-length)/4), 1)+ OCTETSTRING(
      (16-(length+2)), (const unsigned char*)"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0");
    }
    ret_val.attrib__value().encrypted__attrib__value() = f__encrypt__at__encr(key,temp,ivec,false);
  }
  if (tsp__debugging) {
      TTCN_Logger::begin_event(TTCN_DEBUG);
      TTCN_Logger::log_event("AT_ENCR_DATA: ");
      ret_val.log();
      TTCN_Logger::end_event();
  }

  return ret_val;
}

at__aka__encr__data f__crypt__atAKAEncrData(const at__aka__encr__data& pl_encr_data,const OCTETSTRING& key,const OCTETSTRING& ivec,const BOOLEAN& decrypt)
{
  at__aka__encr__data ret_val;
  ret_val.attrib() = pl_encr_data.attrib();
  ret_val.attrib__length()=pl_encr_data.attrib__length();
  ret_val.reserved()=pl_encr_data.reserved();
  if(decrypt)//(pl_encr_data.attrib__value().get_selection()==at__aka__nested::ALT_encrypted__attrib__value)
  {
    OCTETSTRING temp = f__encrypt__at__encr(key,pl_encr_data.attrib__value().encrypted__attrib__value(),ivec,true);
    TTCN_Buffer buf;
    TTCN_EncDec::error_type_t err;
    buf.clear();
    TTCN_EncDec::clear_error();
    TTCN_EncDec::set_error_behavior(TTCN_EncDec::ET_ALL, TTCN_EncDec::EB_WARNING);
    buf.put_os(temp);
    eap__aka__attrib__list vl_attrib_list;
    vl_attrib_list.decode(eap__aka__attrib__list_descr_, buf, TTCN_EncDec::CT_RAW );
    err = TTCN_EncDec::get_last_error_type();
    if(err != TTCN_EncDec::ET_NONE)
      TTCN_warning("Decoding error: %s\n", TTCN_EncDec::get_error_str());
    ret_val.attrib__value().decrypted__attrib__value()=vl_attrib_list;
  }
  else//(pl_encr_data.attrib__value().get_selection()==at__aka__nested::ALT_decrypted__attrib__value)
  {
    TTCN_Buffer buf;
    TTCN_EncDec::error_type_t err;
    buf.clear();
    TTCN_EncDec::clear_error();
    TTCN_EncDec::set_error_behavior(TTCN_EncDec::ET_ALL, TTCN_EncDec::EB_WARNING);
    OCTETSTRING temp;
    if(pl_encr_data.attrib__value().get_selection()==at__aka__nested::ALT_decrypted__attrib__value)
    {
      pl_encr_data.attrib__value().decrypted__attrib__value().encode(eap__aka__attrib__list_descr_, buf, TTCN_EncDec::CT_RAW);
      err = TTCN_EncDec::get_last_error_type();
      if(err != TTCN_EncDec::ET_NONE)
        TTCN_warning("Encoding error: %s\n", TTCN_EncDec::get_error_str());
      temp=OCTETSTRING(buf.get_len(), buf.get_data());
    }
    else
    {
      temp=OCTETSTRING(pl_encr_data.attrib__value().encrypted__attrib__value().lengthof(),pl_encr_data.attrib__value().encrypted__attrib__value());
    }
    if ((temp.lengthof() %16) != 0)
    {
      int length = (temp.lengthof() % 16);
      temp=temp+OCTETSTRING(1, (const unsigned char*)"\6")+int2oct(((16-length)/4), 1)+ OCTETSTRING(
      (16-(length+2)), (const unsigned char*)"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0");
    }
    
    ret_val.attrib__value().encrypted__attrib__value() = f__encrypt__at__encr(key,temp,ivec,false);
  }
  if (tsp__debugging) {
      TTCN_Logger::begin_event(TTCN_DEBUG);
      TTCN_Logger::log_event("AT_ENCR_DATA: ");
      ret_val.log();
      TTCN_Logger::end_event();
  }

  return ret_val;
}

OCTETSTRING f__calc__SRES(const OCTETSTRING& key,const OCTETSTRING& rand)
{
  OCTETSTRING gen_key,gen_rand;
  OCTETSTRING SRES_Value;
  int i;
  if ((rand.lengthof() %16) != 0)
        TTCN_warning("Length of rand should be multiple of 16");
  if (key.lengthof() != 16)
        TTCN_warning("Length of key should be 16");
  int length = (rand.lengthof() / 16);
    gen_key=substr(key,0,4);
    gen_rand=substr(rand,0,4);
  for (i = 1; i < length; i++)
  {
    gen_key=gen_key+substr(key,0,4);
    gen_rand=gen_rand+substr(rand,i*16,4);
  }
  for (i = 0; i < 12; i++)
  {
      SRES_Value[i] = gen_rand[i] ^ gen_key[i];
  }
    return SRES_Value;
}

OCTETSTRING f__calc__A3A8(const OCTETSTRING& key,const OCTETSTRING& rand)
{

  OCTETSTRING gen_key,gen_rand;
  OCTETSTRING A3A8_Value;
  int i;
  if ((rand.lengthof() %16) != 0)
        TTCN_warning("Length of rand should be multiple of 16");
  if (key.lengthof() != 16)
        TTCN_warning("Length of key should be 16");
  int length = (rand.lengthof() / 16);
    gen_key=substr(key,4,8);
    gen_rand=substr(rand,4,8);
  for (i = 1; i < length; i++)
  {
    gen_key=gen_key+substr(key,4,8);
    gen_rand=gen_rand+substr(rand,i*16+4,8);
  }
  for (i = 0; i < (8*length); i++)
  {
      A3A8_Value[i] = gen_rand[i] ^ gen_key[i];
  }
    return A3A8_Value;
} 

const unsigned char * change_ByteOrder(unsigned int in)
{
   static unsigned char out[4] ;
   out[0] = (unsigned char)((in & 0xFF000000) >> 24);
   out[1] = (unsigned char)((in & 0x00FF0000) >> 16);
   out[2] = (unsigned char)((in & 0x0000FF00) >> 8);
   out[3] = (unsigned char)(in & 0x000000FF);
   return out;
} // change_ByteOrder

OCTETSTRING f__calc__Kaut(const OCTETSTRING& input, OCTETSTRING& Kencr)
{  
   unsigned char xval[64];
   unsigned char xkey[SHA_DIGEST_LENGTH];
   SHA1((const unsigned char*)input, input.lengthof(), xkey);
   unsigned char dummy[128];
   unsigned char x_out[80];//40 bytes for each (m) iteration
   int m = 2;

   for(int j = 0; j < m; j++){
    for(int i = 0; i < 2; i++){
      memcpy(xval, xkey, 20);//xval = xkey mod 2^160
      memset(xval + 20, 0, 44);//padding xval to 64 bytes

      SHA_CTX c;
      SHA1_Init(&c);
      SHA1_Update(&c, xval, 64);

      memcpy(x_out + j * 40 + i * 20, change_ByteOrder(c.h0), 4);
      memcpy(x_out + j * 40 + i * 20 + 4, change_ByteOrder(c.h1), 4);
      memcpy(x_out + j * 40 + i * 20 + 8, change_ByteOrder(c.h2), 4);
      memcpy(x_out + j * 40 + i * 20 + 12, change_ByteOrder(c.h3), 4);
      memcpy(x_out + j * 40 + i * 20 + 16, change_ByteOrder(c.h4), 4);//w_i

      BIGNUM * bn1 = BN_new();
      BIGNUM * bn2 = BN_new();
      BIGNUM * bn3 = BN_new();
      if(!bn1 || !bn2 || !bn3)
        TTCN_error("Key generation failed");

      BN_bin2bn(xkey, 20, bn1);//xkey

      BN_one(bn2);//1

      BN_add(bn3, bn1, bn2);//bn3 = xkey + 1

      BN_bin2bn(x_out + j * 40, 20, bn2);//w_i

      BN_add(bn1, bn3, bn2);//bn1 = xkey + 1 + w_i

      BN_bn2bin(bn1, dummy);
      for(int k = 0; k < 20; k++){
        if(BN_num_bytes(bn1) - 1 - k < 0)
          xkey[19 - k] = '\0';
        else
          xkey[19 - k] = dummy[BN_num_bytes(bn1) - 1 - k];
      }//xkey = (xkey + 1 + w_i) mod 2 ^ 160

      BN_free(bn1);
      BN_free(bn2);
      BN_free(bn3);
    }
  }

 Kencr = OCTETSTRING(16, x_out);
 OCTETSTRING Kaut = OCTETSTRING(16, x_out + 16);
 // PMK = OCTETSTRING(32, x_out + 32);
            
  return Kaut;   
}

OCTETSTRING f__calc__AKA__Keys(const OCTETSTRING& pl_eap_identity, const OCTETSTRING& pl_AKA_K,const OCTETSTRING& pl_rand,
               OCTETSTRING& pl_AK,OCTETSTRING& pl_Kaut,OCTETSTRING& pl_Kencr)  
{
  const OCTETSTRING& xdout = pl_AKA_K ^ pl_rand;  
  const OCTETSTRING& IK = xdout <<= 2;
  const OCTETSTRING& CK = xdout <<= 1;
  pl_AK = OCTETSTRING(6, ((const unsigned char*)xdout) + 3);
  pl_Kaut = f__calc__Kaut(pl_eap_identity + IK + CK,pl_Kencr);
  return xdout;
}


void f__initEAPPortDescriptor( EAP__port__descriptor& descriptor)
{
  const OCTETSTRING& null_octetstring = OCTETSTRING(0, (const unsigned char*)NULL);

  for (int i = 0; i < 257; i++) { // keying material, i=256 -> global value
    descriptor.nonce__mt()[i] = null_octetstring;
    descriptor.nonce__s()[i] = null_octetstring;
    descriptor.eap__identity()[i] = null_octetstring;
    descriptor.eap__sim__version__list()[i] = null_octetstring;
    descriptor.eap__sim__selected__version()[i] = null_octetstring;
    descriptor.Kencr()[i] = null_octetstring;
    descriptor.Kaut()[i] = null_octetstring;
    descriptor.Ki()[i] = null_octetstring;
    descriptor.K()[i] = null_octetstring;
    descriptor.SQN()[i] = null_octetstring;
    descriptor.SQN__MS()[i] = null_octetstring;
    descriptor.AMF()[i] = null_octetstring;
    descriptor.AK()[i] = null_octetstring;
    descriptor.XDOUT()[i] = null_octetstring;
    descriptor.n__sres()[i] = null_octetstring;
  }

  descriptor.ivec() = null_octetstring;
  descriptor.nonce() = null_octetstring;
  descriptor.last__calculated__mac() = null_octetstring;
  descriptor.current__identifier() = -1;

  // filling optional parameters with meaningful values
  descriptor.serverMode() =false;

} // initEAPPortDescriptor


void f__get__EAP__parameters(OCTETSTRING& pl_ext_eap_message,EAP__port__descriptor& pl_descriptor,const BOOLEAN& incoming_message)
{
  PDU__EAP__list vl_PDU_EAP_list=f__dec__PDU__EAP__list(pl_ext_eap_message);
  if (tsp__debugging) {
            TTCN_Logger::begin_event(TTCN_DEBUG);
            TTCN_Logger::log_event("EAPs: ");
            vl_PDU_EAP_list.log();
            TTCN_Logger::end_event();
          }
  for (int k=0; k<vl_PDU_EAP_list.size_of();k=k+1)
  {
    if(tsp__global__keying){pl_descriptor.current__identifier()=256;}
    else{pl_descriptor.current__identifier()=vl_PDU_EAP_list[k].identifier();}
    if(((vl_PDU_EAP_list[k].code()==eap__packet__code__enum::request__code) || (vl_PDU_EAP_list[k].code()==eap__packet__code__enum::response__code)) && (vl_PDU_EAP_list[k].packet__length()>4))
    {
      eap__packet__data& vl_packet_data=vl_PDU_EAP_list[k].packet__data()();
      if(vl_packet_data.eap__packet__type()==eap__packet__type__enum::eap__identity)
      {
        pl_descriptor.eap__identity()[pl_descriptor.current__identifier()]=vl_packet_data.eap__packet__type__data().f__eap__identity();
        if (tsp__debugging) {
          TTCN_Logger::begin_event(TTCN_DEBUG);
          TTCN_Logger::log_event("EAP_ID= ");
          pl_descriptor.eap__identity()[pl_descriptor.current__identifier()].log();
          TTCN_Logger::end_event();
        }
       }
      if(vl_packet_data.eap__packet__type()==eap__packet__type__enum::eap__sim)
      {
        for (int i=0;i<vl_packet_data.eap__packet__type__data().f__eap__sim().attrib__list().size_of();i=i+1)
        {
          switch(vl_packet_data.eap__packet__type__data().f__eap__sim().attrib__list()[i].get_selection())
          {
          case eap__sim__attrib::ALT_f__at__version__list:
          {
            int sizeOfVersionList=vl_packet_data.eap__packet__type__data().f__eap__sim().attrib__list()[i].f__at__version__list().version__list().size_of();
            pl_descriptor.eap__sim__version__list()[pl_descriptor.current__identifier()]=vl_packet_data.eap__packet__type__data().f__eap__sim().attrib__list()[i].f__at__version__list().version__list()[0];
            for(int l=1; l<sizeOfVersionList; l=l+1)
            {
              pl_descriptor.eap__sim__version__list()[pl_descriptor.current__identifier()]=pl_descriptor.eap__sim__version__list()[pl_descriptor.current__identifier()] + vl_packet_data.eap__packet__type__data().f__eap__sim().attrib__list()[i].f__at__version__list().version__list()[l];
            }
            if (tsp__debugging) {
              TTCN_Logger::begin_event(TTCN_DEBUG);
              TTCN_Logger::log_event("EAP_SIM_VERSION_LIST= ");
              pl_descriptor.eap__sim__version__list()[pl_descriptor.current__identifier()].log();
              TTCN_Logger::end_event();
            }
          }
          break;
          case eap__sim__attrib::ALT_f__at__nonce__mt:
          {
            pl_descriptor.nonce__mt()[pl_descriptor.current__identifier()]=vl_packet_data.eap__packet__type__data().f__eap__sim().attrib__list()[i].f__at__nonce__mt().attrib__value();
            if (tsp__debugging) {
              TTCN_Logger::begin_event(TTCN_DEBUG);
              TTCN_Logger::log_event("EAP_SIM_NONCE_MT= ");
              pl_descriptor.nonce__mt()[pl_descriptor.current__identifier()].log();
              TTCN_Logger::end_event();
            }
          }
          break;
          case eap__sim__attrib::ALT_f__at__selected__version:
          {
            pl_descriptor.eap__sim__selected__version()[pl_descriptor.current__identifier()]=vl_packet_data.eap__packet__type__data().f__eap__sim().attrib__list()[i].f__at__selected__version().attrib__data();
            if (tsp__debugging) {
              TTCN_Logger::begin_event(TTCN_DEBUG);
              TTCN_Logger::log_event("EAP_SIM_SELECTED_VERSION= ");
              pl_descriptor.eap__sim__selected__version()[pl_descriptor.current__identifier()].log();
              TTCN_Logger::end_event();
            }
          }
          break;
          case eap__sim__attrib::ALT_f__at__iv:
          {
            pl_descriptor.ivec()=vl_packet_data.eap__packet__type__data().f__eap__sim().attrib__list()[i].f__at__iv().attrib__value();
            if (tsp__debugging) {
              TTCN_Logger::begin_event(TTCN_DEBUG);
              TTCN_Logger::log_event("EAP_SIM_IVEC= ");
              pl_descriptor.ivec().log();
              TTCN_Logger::end_event();
            }
          }
          break;
          case eap__sim__attrib::ALT_f__at__rand:
          {
            int sizeOfRandList=vl_packet_data.eap__packet__type__data().f__eap__sim().attrib__list()[i].f__at__rand().attrib__value().size_of();
            OCTETSTRING vl_randlist=vl_packet_data.eap__packet__type__data().f__eap__sim().attrib__list()[i].f__at__rand().attrib__value()[0];
            for(int l=1; l<sizeOfRandList; l=l+1)
            {
              vl_randlist += vl_packet_data.eap__packet__type__data().f__eap__sim().attrib__list()[i].f__at__rand().attrib__value()[l];
            }
            if (tsp__debugging) {
              TTCN_Logger::begin_event(TTCN_DEBUG);
              TTCN_Logger::log_event("EAP_SIM_RAND_LIST= ");
              vl_randlist.log();
              TTCN_Logger::end_event();
            }
            if(!tsp__skip__auth__encr)
            {
              if(pl_descriptor.Ki()[pl_descriptor.current__identifier()].lengthof()==0){pl_descriptor.Ki()[pl_descriptor.current__identifier()]=tsp__SIM__Ki;}
              pl_descriptor.n__sres()[pl_descriptor.current__identifier()]=f__calc__SRES(pl_descriptor.Ki()[pl_descriptor.current__identifier()],vl_randlist);
              OCTETSTRING vl_A3A8=f__calc__A3A8(pl_descriptor.Ki()[pl_descriptor.current__identifier()],vl_randlist);
              if (tsp__debugging) {
                TTCN_Logger::begin_event(TTCN_DEBUG);
                TTCN_Logger::log_event("n*SRES= ");
                pl_descriptor.n__sres()[pl_descriptor.current__identifier()].log();
                TTCN_Logger::log_event("A3A8= ");
                vl_A3A8.log();
                TTCN_Logger::end_event();
              }
              bool missParams=false;
              if(pl_descriptor.eap__identity()[pl_descriptor.current__identifier()].lengthof()==0){TTCN_warning("Missing EAP_Identity!");missParams=true;}
              if(pl_descriptor.nonce__mt()[pl_descriptor.current__identifier()].lengthof()==0){TTCN_warning("Missing NONCE_MT!");missParams=true;}
              if(pl_descriptor.eap__sim__version__list()[pl_descriptor.current__identifier()].lengthof()==0){TTCN_warning("Missing EAP_SIM_Version_List!");missParams=true;}
              if(missParams==false)
              {
                pl_descriptor.Kaut()[pl_descriptor.current__identifier()]=
                  f__calc__Kaut(
                      pl_descriptor.eap__identity()[pl_descriptor.current__identifier()] +
                      vl_A3A8 +
                      pl_descriptor.nonce__mt()[pl_descriptor.current__identifier()] +
                      pl_descriptor.eap__sim__version__list()[pl_descriptor.current__identifier()] +
                      pl_descriptor.eap__sim__selected__version()[pl_descriptor.current__identifier()],
                      pl_descriptor.Kencr()[pl_descriptor.current__identifier()]);
                if (tsp__debugging) {
                  TTCN_Logger::begin_event(TTCN_DEBUG);
                  TTCN_Logger::log_event("KAUT= ");
                  pl_descriptor.Kaut()[pl_descriptor.current__identifier()].log();
                  TTCN_Logger::log_event("KENCR= ");
                  pl_descriptor.Kencr()[pl_descriptor.current__identifier()].log();
                  TTCN_Logger::end_event();
                }
              }
            }
          }
          break;
          case eap__sim__attrib::ALT_f__at__encr__data:
          {
            if (tsp__debugging) {
              TTCN_Logger::begin_event(TTCN_DEBUG);
              TTCN_Logger::log_event("ENCR_DATA= ");
              vl_packet_data.eap__packet__type__data().f__eap__sim().attrib__list()[i].f__at__encr__data().log();
              TTCN_Logger::end_event();
            }
            at__sim__encr__data vl_decr_data;
            eap__sim__attrib__list vl_eap_sim_attrib_list=NULL_VALUE;
            if (incoming_message == false)
            {
              vl_decr_data=vl_packet_data.eap__packet__type__data().f__eap__sim().attrib__list()[i].f__at__encr__data();
              vl_eap_sim_attrib_list=f__dec__eap__sim__attrib__list(vl_decr_data.attrib__value().encrypted__attrib__value());
              at__sim__encr__data vl_encr_data=f__crypt__atSimEncrData(vl_packet_data.eap__packet__type__data().f__eap__sim().attrib__list()[i].f__at__encr__data(),
                  pl_descriptor.Kencr()[pl_descriptor.current__identifier()],
                  pl_descriptor.ivec(),false);
              vl_packet_data.eap__packet__type__data().f__eap__sim().attrib__list()[i].f__at__encr__data()=vl_encr_data;
              vl_encr_data=vl_packet_data.eap__packet__type__data().f__eap__sim().attrib__list()[i].f__at__encr__data();
            }
            else 
            {
              if (!tsp__skip__auth__encr)
              {
                vl_decr_data=f__crypt__atSimEncrData(vl_packet_data.eap__packet__type__data().f__eap__sim().attrib__list()[i].f__at__encr__data(),
                  pl_descriptor.Kencr()[pl_descriptor.current__identifier()],pl_descriptor.ivec(),true);
                vl_eap_sim_attrib_list=vl_decr_data.attrib__value().decrypted__attrib__value();
                if (tsp__debugging) {
                  TTCN_Logger::begin_event(TTCN_DEBUG);
                  TTCN_Logger::log_event("DECRYPTED DATA= ");
                  vl_eap_sim_attrib_list.log();
                  TTCN_Logger::end_event();
                }
              }
              else{TTCN_warning("Decryption of EAP-AKA AT_ENCR_DATA skipped.");}
           }
            for (int m=0; m<vl_eap_sim_attrib_list.size_of();m=m+1)
            {
              if(vl_eap_sim_attrib_list[m].get_selection()==eap__sim__attrib::ALT_f__at__nonce__s)
              {
                pl_descriptor.nonce__s()[pl_descriptor.current__identifier()]=vl_eap_sim_attrib_list[m].f__at__nonce__s().attrib__value();
                if (tsp__debugging) {
                  TTCN_Logger::begin_event(TTCN_DEBUG);
                  TTCN_Logger::log_event("NONCE_S= ");
                  pl_descriptor.nonce__s()[pl_descriptor.current__identifier()].log();
                  TTCN_Logger::end_event();
                }
              }
            }
          }
          break;
          case eap__sim__attrib::ALT_f__at__mac:
          {
            if (pl_descriptor.serverMode() == true)
            {
              if(incoming_message == false) // Generating AT_MAC
              {
                if(vl_packet_data.eap__packet__type__data().f__eap__sim().attrib__list()[i].f__at__mac().attrib__value() == OCTETSTRING(16, (const unsigned char*)"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"))
                {
                  OCTETSTRING vl_in=f__enc__PDU__EAP(vl_PDU_EAP_list[k]);
                  if (vl_packet_data.eap__packet__type__data().f__eap__sim().subtype()==eap__sim__subtype__enum::eap__sim__re__authentication)
                  {pl_descriptor.nonce()=(pl_descriptor.nonce__s()[pl_descriptor.current__identifier()]);}
                  else if (vl_packet_data.eap__packet__type__data().f__eap__sim().subtype()==eap__sim__subtype__enum::eap__sim__challenge)
                  {pl_descriptor.nonce()= (pl_descriptor.nonce__mt()[pl_descriptor.current__identifier()]);}
                  else{pl_descriptor.nonce()=OCTETSTRING(0,(const unsigned char*)NULL);}
                  vl_in = vl_in + (pl_descriptor.nonce());
                  vl_packet_data.eap__packet__type__data().f__eap__sim().attrib__list()[i].f__at__mac().attrib__value()=
                    f__calc__HMAC(pl_descriptor.Kaut()[pl_descriptor.current__identifier()],vl_in,16);
                }
                pl_descriptor.last__calculated__mac() =vl_packet_data.eap__packet__type__data().f__eap__sim().attrib__list()[i].f__at__mac().attrib__value(); 
              }//if(incoming_message == false)
              else // Checking AT_MAC
              {
                if(tsp__skip__auth__encr){TTCN_warning("Checking of AT_MAC skipped.");}
                else
                {
                  OCTETSTRING vl_atMAC=vl_packet_data.eap__packet__type__data().f__eap__sim().attrib__list()[i].f__at__mac().attrib__value();
                  vl_packet_data.eap__packet__type__data().f__eap__sim().attrib__list()[i].f__at__mac().attrib__value()=OCTETSTRING(16, (const unsigned char*)"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0");
                  OCTETSTRING vl_in=f__enc__PDU__EAP(vl_PDU_EAP_list[k]);
                  if (vl_packet_data.eap__packet__type__data().f__eap__sim().subtype()==eap__sim__subtype__enum::eap__sim__challenge)
                  {vl_in += pl_descriptor.n__sres()[pl_descriptor.current__identifier()];}
                  vl_packet_data.eap__packet__type__data().f__eap__sim().attrib__list()[i].f__at__mac().attrib__value()= f__calc__HMAC(pl_descriptor.Kaut()[pl_descriptor.current__identifier()],vl_in,16);
                  if(vl_packet_data.eap__packet__type__data().f__eap__sim().attrib__list()[i].f__at__mac().attrib__value()!=vl_atMAC)
                  {TTCN_warning("Invalid AT_MAC!");}
                }
              }
            }//if (serverMode == true)
            else //serverMode == false
            {
              if(incoming_message == false) // Generating AT_MAC
              {
                if(vl_packet_data.eap__packet__type__data().f__eap__sim().attrib__list()[i].f__at__mac().attrib__value() == OCTETSTRING(16, (const unsigned char*)"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"))
                {
                  OCTETSTRING vl_in=f__enc__PDU__EAP(vl_PDU_EAP_list[k]);
                  if (vl_packet_data.eap__packet__type__data().f__eap__sim().subtype()==eap__sim__subtype__enum::eap__sim__re__authentication)
                  {pl_descriptor.nonce()=OCTETSTRING(0,(const unsigned char*)NULL);}
                  else if (vl_packet_data.eap__packet__type__data().f__eap__sim().subtype()==eap__sim__subtype__enum::eap__sim__challenge)
                  {pl_descriptor.nonce()=(pl_descriptor.n__sres()[pl_descriptor.current__identifier()]);}
                  else{pl_descriptor.nonce()=OCTETSTRING(0,(const unsigned char*)NULL);}
                  vl_in += pl_descriptor.nonce();
                  vl_packet_data.eap__packet__type__data().f__eap__sim().attrib__list()[i].f__at__mac().attrib__value()=
                    f__calc__HMAC(pl_descriptor.Kaut()[pl_descriptor.current__identifier()],vl_in,16);
                }
                pl_descriptor.last__calculated__mac() =vl_packet_data.eap__packet__type__data().f__eap__sim().attrib__list()[i].f__at__mac().attrib__value(); 
              }//if(incoming_message == false)
              else // Checking AT_MAC
              {
                if(tsp__skip__auth__encr){TTCN_warning("Checking of AT_MAC skipped.");}
                else
                {
                  OCTETSTRING vl_atMAC=vl_packet_data.eap__packet__type__data().f__eap__sim().attrib__list()[i].f__at__mac().attrib__value();
                  vl_packet_data.eap__packet__type__data().f__eap__sim().attrib__list()[i].f__at__mac().attrib__value()=OCTETSTRING(16, (const unsigned char*)"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0");
                  OCTETSTRING vl_in=f__enc__PDU__EAP(vl_PDU_EAP_list[k]);
                  if (vl_packet_data.eap__packet__type__data().f__eap__sim().subtype()==eap__sim__subtype__enum::eap__sim__challenge)
                  {vl_in += pl_descriptor.nonce__mt()[pl_descriptor.current__identifier()];}
                  else if (vl_packet_data.eap__packet__type__data().f__eap__sim().subtype()==eap__sim__subtype__enum::eap__sim__re__authentication)
                  {vl_in += pl_descriptor.nonce__s()[pl_descriptor.current__identifier()];}
                  vl_packet_data.eap__packet__type__data().f__eap__sim().attrib__list()[i].f__at__mac().attrib__value()= f__calc__HMAC(pl_descriptor.Kaut()[pl_descriptor.current__identifier()],vl_in,16);
                  if(vl_packet_data.eap__packet__type__data().f__eap__sim().attrib__list()[i].f__at__mac().attrib__value()!=vl_atMAC)
                  {TTCN_warning("Invalid AT_MAC!");}
                }
              }
            }//if(serverMode == false)
          }
          break;
          default:
//            TTCN_warning("Invalid EAP SIM attribute!");
          break;
          }

          pl_ext_eap_message=f__enc__PDU__EAP__list(vl_PDU_EAP_list);
        }
      }
      if(vl_packet_data.eap__packet__type()==eap__packet__type__enum::eap__aka)
      {
        for (int i=0;i<vl_packet_data.eap__packet__type__data().f__eap__aka().attrib__list().size_of();i=i+1)
        {
          switch(vl_packet_data.eap__packet__type__data().f__eap__aka().attrib__list()[i].get_selection())
          {
          case eap__aka__attrib::ALT_f__at__rand:
          {
            OCTETSTRING vl_rand=vl_packet_data.eap__packet__type__data().f__eap__aka().attrib__list()[i].f__at__rand().attrib__value();
            if (tsp__debugging) {
              TTCN_Logger::begin_event(TTCN_DEBUG);
              TTCN_Logger::log_event("EAP_AKA_RAND= ");
              vl_rand.log();
              TTCN_Logger::end_event();
            }
            if (!tsp__skip__auth__encr)
            {
              if(pl_descriptor.eap__identity()[pl_descriptor.current__identifier()].lengthof()==0){TTCN_warning("Missing EAP Identity!");}
              if(pl_descriptor.K()[pl_descriptor.current__identifier()].lengthof()==0){pl_descriptor.K()[pl_descriptor.current__identifier()]=tsp__AKA__K;}
              pl_descriptor.XDOUT()[pl_descriptor.current__identifier()]=
                f__calc__AKA__Keys(pl_descriptor.eap__identity()[pl_descriptor.current__identifier()],pl_descriptor.K()[pl_descriptor.current__identifier()],vl_rand,
                pl_descriptor.AK()[pl_descriptor.current__identifier()],pl_descriptor.Kaut()[pl_descriptor.current__identifier()],pl_descriptor.Kencr()[pl_descriptor.current__identifier()]);
              if (tsp__debugging) {
                TTCN_Logger::begin_event(TTCN_DEBUG);
                TTCN_Logger::log_event("XDOUT= ");
                pl_descriptor.XDOUT()[pl_descriptor.current__identifier()].log();
                TTCN_Logger::log_event("AK= ");
                pl_descriptor.AK()[pl_descriptor.current__identifier()].log();
                TTCN_Logger::log_event("Kaut= ");
                pl_descriptor.Kaut()[pl_descriptor.current__identifier()].log();
                TTCN_Logger::log_event("Kencr= ");
                pl_descriptor.Kencr()[pl_descriptor.current__identifier()].log();
                TTCN_Logger::end_event();
              }
            }
            else{TTCN_warning("Skipped calculating EAP AKA keys!");}
          }
          break;
          case eap__aka__attrib::ALT_f__at__iv:
          {
            pl_descriptor.ivec()=vl_packet_data.eap__packet__type__data().f__eap__aka().attrib__list()[i].f__at__iv().attrib__value();
            if (tsp__debugging) {
              TTCN_Logger::begin_event(TTCN_DEBUG);
              TTCN_Logger::log_event("EAP_AKA_IVEC= ");
              pl_descriptor.ivec().log();
              TTCN_Logger::end_event();
            }
          }
          break;
          case eap__aka__attrib::ALT_f__at__res:
          {
            if (incoming_message == false)
            {
              if(vl_packet_data.eap__packet__type__data().f__eap__aka().attrib__list()[i].f__at__res().attrib__value() == OCTETSTRING(16, (const unsigned char*)"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"))
              {
                vl_packet_data.eap__packet__type__data().f__eap__aka().attrib__list()[i].f__at__res().attrib__value()=pl_descriptor.XDOUT()[pl_descriptor.current__identifier()];
              }
            }
            if(vl_packet_data.eap__packet__type__data().f__eap__aka().attrib__list()[i].f__at__res().attrib__value() != pl_descriptor.XDOUT()[pl_descriptor.current__identifier()])
            {
              TTCN_warning("Bad AKA AT_RES!");
            }
          }
          break;
          case eap__aka__attrib::ALT_f__at__encr__data:
          {
            at__aka__encr__data vl_decr_data;
            eap__aka__attrib__list vl_eap_aka_attrib_list=NULL_VALUE;
            if (incoming_message == false)
            {
              vl_decr_data=vl_packet_data.eap__packet__type__data().f__eap__aka().attrib__list()[i].f__at__encr__data();
              vl_eap_aka_attrib_list=f__dec__eap__aka__attrib__list(vl_decr_data.attrib__value().encrypted__attrib__value());
              at__aka__encr__data vl_encr_data=f__crypt__atAKAEncrData(vl_packet_data.eap__packet__type__data().f__eap__aka().attrib__list()[i].f__at__encr__data(),
                  pl_descriptor.Kencr()[pl_descriptor.current__identifier()],
                  pl_descriptor.ivec(),false);
              vl_packet_data.eap__packet__type__data().f__eap__aka().attrib__list()[i].f__at__encr__data()=vl_encr_data;
              vl_encr_data=vl_packet_data.eap__packet__type__data().f__eap__aka().attrib__list()[i].f__at__encr__data();
            }
            else 
            {
              if (!tsp__skip__auth__encr)
              {
                vl_decr_data=f__crypt__atAKAEncrData(vl_packet_data.eap__packet__type__data().f__eap__aka().attrib__list()[i].f__at__encr__data(),
                  pl_descriptor.Kencr()[pl_descriptor.current__identifier()],pl_descriptor.ivec(),true);
                vl_eap_aka_attrib_list=vl_decr_data.attrib__value().decrypted__attrib__value();
              }
              else{TTCN_warning("Decryption of EAP-AKA AT_ENCR_DATA skipped.");}
            }
            for (int m=0; m<vl_eap_aka_attrib_list.size_of();m=m+1)
            {
              if(vl_eap_aka_attrib_list[m].get_selection()==eap__aka__attrib::ALT_f__at__nonce__s)
              {
                pl_descriptor.nonce__s()[pl_descriptor.current__identifier()]=vl_eap_aka_attrib_list[m].f__at__nonce__s().attrib__value();
                if (tsp__debugging) {
                  TTCN_Logger::begin_event(TTCN_DEBUG);
                  TTCN_Logger::log_event("NONCE_S= ");
                  pl_descriptor.nonce__s()[pl_descriptor.current__identifier()].log();
                  TTCN_Logger::end_event();
                }
              }
            }
          }
          break;
          case eap__aka__attrib::ALT_f__at__autn:
          {
            if (!tsp__skip__auth__encr)
            {
              if (incoming_message == false) {
                if (pl_descriptor.AK()[pl_descriptor.current__identifier()].lengthof() != 6)
                {TTCN_warning("Bad length of AK. Possibly you have not sent AT_RAND.");}
                if(pl_descriptor.SQN()[pl_descriptor.current__identifier()].lengthof()!=6){pl_descriptor.SQN()[pl_descriptor.current__identifier()]=tsp__AKA__SQN;}
                if(pl_descriptor.AMF()[pl_descriptor.current__identifier()].lengthof()!=2){pl_descriptor.AMF()[pl_descriptor.current__identifier()]=tsp__AKA__AMF;}
                const OCTETSTRING& encr_sqn = pl_descriptor.SQN()[pl_descriptor.current__identifier()] ^ pl_descriptor.AK() [pl_descriptor.current__identifier()];
                const OCTETSTRING& cdout = pl_descriptor.SQN()[pl_descriptor.current__identifier()] + pl_descriptor.AMF()[pl_descriptor.current__identifier()];
                const OCTETSTRING& xmac = OCTETSTRING(8, (const unsigned char*)pl_descriptor.XDOUT()[pl_descriptor.current__identifier()]) ^ cdout;
                const OCTETSTRING& calculated_autn = encr_sqn + pl_descriptor.AMF()[pl_descriptor.current__identifier()] + xmac;

                if (vl_packet_data.eap__packet__type__data().f__eap__aka().attrib__list()[i].f__at__autn().attrib__value() != OCTETSTRING(16, (const unsigned char*)"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"))
                {
                  if (vl_packet_data.eap__packet__type__data().f__eap__aka().attrib__list()[i].f__at__autn().attrib__value() != calculated_autn)
                    TTCN_warning("Invalid AT_AUTN on sending.");
                }
                else
                {
                  vl_packet_data.eap__packet__type__data().f__eap__aka().attrib__list()[i].f__at__autn().attrib__value() = calculated_autn;
                } 
               
              }
              else
              {
                pl_descriptor.SQN()[pl_descriptor.current__identifier()] = OCTETSTRING(6, (const unsigned char*)vl_packet_data.eap__packet__type__data().f__eap__aka().attrib__list()[i].f__at__autn().attrib__value()) ^ pl_descriptor.AK()[pl_descriptor.current__identifier()];
                pl_descriptor.AMF()[pl_descriptor.current__identifier()] = OCTETSTRING (2, ((const unsigned char*)vl_packet_data.eap__packet__type__data().f__eap__aka().attrib__list()[i].f__at__autn().attrib__value()) + 6);

                const OCTETSTRING& cdout = pl_descriptor.SQN()[pl_descriptor.current__identifier()] + pl_descriptor.AMF()[pl_descriptor.current__identifier()];
                const OCTETSTRING& xmac = OCTETSTRING(8, (const unsigned char*)pl_descriptor.XDOUT()[pl_descriptor.current__identifier()]) ^ cdout;
                const OCTETSTRING& received_aka_mac = OCTETSTRING(8, ((const unsigned char*)vl_packet_data.eap__packet__type__data().f__eap__aka().attrib__list()[i].f__at__autn().attrib__value()) + 8);
                if (received_aka_mac != xmac)
                  TTCN_warning("Invalid AKA MAC within AT_AUTN.");
              }
            }
          }
          break;
          case eap__aka__attrib::ALT_f__at__auts: 
          {
            if (!tsp__skip__auth__encr)
            {
              if (incoming_message == false)
              {
                if (pl_descriptor.AK()[pl_descriptor.current__identifier()].lengthof() != 6)
                TTCN_warning("Bad length of AK. Possibly you have not sent AT_RAND.");
                if(pl_descriptor.SQN__MS()[pl_descriptor.current__identifier()].lengthof()!=6){pl_descriptor.SQN__MS()[pl_descriptor.current__identifier()]=tsp__AKA__SQN__MS;}

                const OCTETSTRING& encr_sqn_ms = pl_descriptor.SQN__MS()[pl_descriptor.current__identifier()] ^ pl_descriptor.AK()[pl_descriptor.current__identifier()];
                const OCTETSTRING& CDOUT = pl_descriptor.SQN__MS()[pl_descriptor.current__identifier()] + OCTETSTRING(2, (const unsigned char*)"\0\0");
                const OCTETSTRING& calculated_mac_s = OCTETSTRING(8, (const unsigned char*)pl_descriptor.XDOUT()[pl_descriptor.current__identifier()]) ^ CDOUT;
                const OCTETSTRING& calculated_auts = encr_sqn_ms + calculated_mac_s;

                if (vl_packet_data.eap__packet__type__data().f__eap__aka().attrib__list()[i].f__at__auts().attrib__value() == OCTETSTRING(14, (const unsigned char*)"\0\0\0\0\0\0\0\0\0\0\0\0\0\0"))
                {vl_packet_data.eap__packet__type__data().f__eap__aka().attrib__list()[i].f__at__auts().attrib__value() = calculated_auts;}
                else {
                  if (calculated_auts != vl_packet_data.eap__packet__type__data().f__eap__aka().attrib__list()[i].f__at__auts().attrib__value())
                  {TTCN_warning("Invalid AT_AUTS on sending.");}
                }
              }
              else
              {
                if (pl_descriptor.AK()[pl_descriptor.current__identifier()].lengthof() != 6)
                  TTCN_warning("Bad length of AK. Possibly AT_RAND attribute has not been sent yet).");

                pl_descriptor.SQN__MS()[pl_descriptor.current__identifier()] = OCTETSTRING(6, (const unsigned char*)vl_packet_data.eap__packet__type__data().f__eap__aka().attrib__list()[i].f__at__auts().attrib__value()) ^ pl_descriptor.AK()[pl_descriptor.current__identifier()];
                const OCTETSTRING& cdout = pl_descriptor.SQN__MS()[pl_descriptor.current__identifier()] + OCTETSTRING(2, (const unsigned char*)"\0\0");

                const OCTETSTRING& xmac_s = OCTETSTRING(8, (const unsigned char*)pl_descriptor.XDOUT()[pl_descriptor.current__identifier()]) ^ cdout;
                const OCTETSTRING& received_aka_mac_s = OCTETSTRING(8, ((const unsigned char*)vl_packet_data.eap__packet__type__data().f__eap__aka().attrib__list()[i].f__at__auts().attrib__value())  + 6);
                if (received_aka_mac_s != xmac_s)
                  TTCN_warning("Invalid AKA MAC_S within AT_AUTN.");
              }
            }
          }
          break;
          case eap__aka__attrib::ALT_f__at__mac:
          {
            if (pl_descriptor.serverMode() == true)
            {
              if(incoming_message == false) // Generating AT_MAC
              {
                if(vl_packet_data.eap__packet__type__data().f__eap__aka().attrib__list()[i].f__at__mac().attrib__value() == OCTETSTRING(16, (const unsigned char*)"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"))
                {
                  OCTETSTRING vl_in=f__enc__PDU__EAP(vl_PDU_EAP_list[k]);
                  if (vl_packet_data.eap__packet__type__data().f__eap__aka().subtype()==eap__aka__subtype__enum::eap__aka__reauthentication)
                  {pl_descriptor.nonce()=(pl_descriptor.nonce__s()[pl_descriptor.current__identifier()]);}
                  else{pl_descriptor.nonce()=OCTETSTRING(0,(const unsigned char*)NULL);}
                  vl_in += pl_descriptor.nonce();
                  vl_packet_data.eap__packet__type__data().f__eap__aka().attrib__list()[i].f__at__mac().attrib__value()=
                    f__calc__HMAC(pl_descriptor.Kaut()[pl_descriptor.current__identifier()],vl_in,16);
                }
                pl_descriptor.last__calculated__mac() =vl_packet_data.eap__packet__type__data().f__eap__aka().attrib__list()[i].f__at__mac().attrib__value(); 
              }//if(incoming_message == false)
              else // Checking AT_MAC
              {
                if(tsp__skip__auth__encr){TTCN_warning("Checking of AT_MAC skipped.");}
                else
                {
                  OCTETSTRING vl_atMAC=vl_packet_data.eap__packet__type__data().f__eap__aka().attrib__list()[i].f__at__mac().attrib__value();
                  vl_packet_data.eap__packet__type__data().f__eap__aka().attrib__list()[i].f__at__mac().attrib__value()=OCTETSTRING(16, (const unsigned char*)"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0");
                  OCTETSTRING vl_in=f__enc__PDU__EAP(vl_PDU_EAP_list[k]);
                  vl_packet_data.eap__packet__type__data().f__eap__aka().attrib__list()[i].f__at__mac().attrib__value()= f__calc__HMAC(pl_descriptor.Kaut()[pl_descriptor.current__identifier()],vl_in,16);
                  if(vl_packet_data.eap__packet__type__data().f__eap__aka().attrib__list()[i].f__at__mac().attrib__value()!=vl_atMAC)
                  {TTCN_warning("Invalid AT_MAC!");}
                }
              }
            }//if (serverMode == true)
            else //serverMode == false
            {
              if(incoming_message == false) // Generating AT_MAC
              {
                if(vl_packet_data.eap__packet__type__data().f__eap__aka().attrib__list()[i].f__at__mac().attrib__value() == OCTETSTRING(16, (const unsigned char*)"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"))
                {
                  OCTETSTRING vl_in=f__enc__PDU__EAP(vl_PDU_EAP_list[k]);
                  vl_packet_data.eap__packet__type__data().f__eap__aka().attrib__list()[i].f__at__mac().attrib__value()=
                    f__calc__HMAC(pl_descriptor.Kaut()[pl_descriptor.current__identifier()],vl_in,16);
                }
                pl_descriptor.last__calculated__mac() =vl_packet_data.eap__packet__type__data().f__eap__aka().attrib__list()[i].f__at__mac().attrib__value(); 
              }//if(incoming_message == false)
              else // Checking AT_MAC
              {
                if(tsp__skip__auth__encr){TTCN_warning("Checking of AT_MAC skipped.");}
                else
                {
                  OCTETSTRING vl_atMAC=vl_packet_data.eap__packet__type__data().f__eap__aka().attrib__list()[i].f__at__mac().attrib__value();
                  vl_packet_data.eap__packet__type__data().f__eap__aka().attrib__list()[i].f__at__mac().attrib__value()=OCTETSTRING(16, (const unsigned char*)"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0");
                  OCTETSTRING vl_in=f__enc__PDU__EAP(vl_PDU_EAP_list[k]);
                  if (vl_packet_data.eap__packet__type__data().f__eap__aka().subtype()==eap__aka__subtype__enum::eap__aka__reauthentication)
                  {pl_descriptor.nonce()=(pl_descriptor.nonce__s()[pl_descriptor.current__identifier()]);}
                  else{pl_descriptor.nonce()=OCTETSTRING(0,(const unsigned char*)NULL);}
                  vl_in += pl_descriptor.nonce();
                  vl_packet_data.eap__packet__type__data().f__eap__aka().attrib__list()[i].f__at__mac().attrib__value()= f__calc__HMAC(pl_descriptor.Kaut()[pl_descriptor.current__identifier()],vl_in,16);
                  if(vl_packet_data.eap__packet__type__data().f__eap__aka().attrib__list()[i].f__at__mac().attrib__value()!=vl_atMAC)
                  {TTCN_warning("Invalid AT_MAC!");}
                }
              }
            }//if(serverMode == false)
          }
          break;
          default:
//            TTCN_warning("Invalid EAP AKA attribute!");
          break;
          }
          pl_ext_eap_message=f__enc__PDU__EAP__list(vl_PDU_EAP_list);
        }
      }
    }
  }
}

OCTETSTRING f__enc__PDU__EAP__list(const PDU__EAP__list& pl_PDU_EAP_list)
{
    if (tsp__debugging) {
        TTCN_Logger::begin_event(TTCN_DEBUG);
        TTCN_Logger::log_event("Encoding PDU_EAP_list: ");
        pl_PDU_EAP_list.log();
        TTCN_Logger::end_event();
    }
    
    TTCN_Buffer buf;
    int pl_PDU_EAP_size = pl_PDU_EAP_list.size_of();
    for(int index = 0; index < pl_PDU_EAP_size; index++)
    {
      pl_PDU_EAP_list[index].encode(EAP__Types::PDU__EAP_descr_, buf, TTCN_EncDec::CT_RAW);
    }
    OCTETSTRING ret_val(buf.get_len(), buf.get_data());

    if (tsp__debugging) {
        TTCN_Logger::begin_event(TTCN_DEBUG);
        TTCN_Logger::log_event("PDU_EAP_list after encoding: ");
        ret_val.log();
        TTCN_Logger::end_event();
    }
    return ret_val;
}

PDU__EAP__list f__dec__PDU__EAP__list(const OCTETSTRING& pl_stream)
{
    TTCN_Buffer buf;
    buf.put_s( pl_stream.lengthof(), pl_stream);
    
    PDU__EAP__list ret_val;
    ret_val.set_size(0); 
    int index = 0;    
        
    while(buf.get_read_len() > 0)  
    { 
    ret_val[index].decode(EAP__Types::PDU__EAP_descr_, buf, TTCN_EncDec::CT_RAW); 
    index = index + 1;  
    }
    
    if (tsp__debugging) {
        TTCN_Logger::begin_event(TTCN_DEBUG);
        TTCN_Logger::log_event("Decoded PDU_EAP_list: ");
        ret_val.log();
        TTCN_Logger::end_event();
    }
    
    return ret_val;
}


}
TTCN_Module EAP_EncDec("EAP_EncDec", __DATE__, __TIME__);
