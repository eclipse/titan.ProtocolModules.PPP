/******************************************************************************
* Copyright (c) 2008, 2015  Ericsson AB
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
//  File:               PPP_EncDec.cc
//  Rev:                R2A
//  Prodnr:             CNL 113 599
//  Reference:          RFC 1661(PPP), 1332(IPCP), 1877, 1994(CHAP), 1334(PAP) 
//                      3748(EAP) and RFC 1662 (Address and Control fields in Frame)
// 

#include "PPP_Types.hh"
#include "IP_Types.hh"
using namespace EAP__Types;
namespace PPP__Types {


//////////////////////////////////
// Decoding function for PPP Types
//////////////////////////////////
PDU__PPP dec__PDU__PPP(const OCTETSTRING& stream)
{
  TTCN_Buffer buf;
  PDU__PPP pdu;
  int lengthinfo; 
  Information info;
  LCP elcp;
  IPCP eipcp;
  CHAP echap;
  PAP epap;
  PDU__EAP eeap;
  IP__Types::IPv4__packet eip4;
    
  //Determine if address and header fields are present
  const unsigned char* stream_ptr = (const unsigned char*)stream;
  if  ((stream_ptr[0] == 0xff) && (stream_ptr[1] == 0x03)) 
  {   
    pdu.pPP__AddressControl() = substr(stream,0,2); // 'FF03'O
    pdu.protocol() = substr(stream,2,2);
    
             
    lengthinfo = oct2int(substr(stream,6,2));
    
    buf.put_os(substr(stream,4,lengthinfo));
    
    if  (stream_ptr[3] == 0x21) 
    {
      if (stream_ptr[2] == 0xc0)
      {
        elcp.decode(LCP_descr_, buf, TTCN_EncDec::CT_RAW);
        pdu.information().lcp() = elcp;
      }
      else
      {
        if (stream_ptr[2] == 0x80)
        {
          eipcp.decode(IPCP_descr_, buf, TTCN_EncDec::CT_RAW);
          pdu.information().ipcp() = eipcp;
        }
        else
        {
          if(stream_ptr[2] == 0x00)
          {
           //imported from CNL 113 418 IP Protocol Module
           pdu.information().ip4() = IP__Types::f__IPv4__dec(OCTETSTRING(lengthinfo, buf.get_read_data()));
          }
          else{
            TTCN_warning("Unsupported PPP message received with protocol :%x %x",stream_ptr[2],stream_ptr[3]);
          }
        }
      }
    }
    else
    {
      if (stream_ptr[3] == 0x23) 
      {
        if (stream_ptr[2] == 0xc2)
        {
          echap.decode(CHAP_descr_, buf, TTCN_EncDec::CT_RAW);
          pdu.information().chap() = echap;
        }
        else
        {
          if (stream_ptr[2] == 0xc0)
          {
            epap.decode(PAP_descr_, buf, TTCN_EncDec::CT_RAW);
            pdu.information().pap() = epap;
          }
          else TTCN_warning("Unsupported PPP message received with protocol :%x %x",stream_ptr[2],stream_ptr[3]);
        }
      }
      else if (stream_ptr[3] == 0x27)
      {
          if (stream_ptr[2] == 0xc2)
          {
            eeap.decode(PDU__EAP_descr_, buf, TTCN_EncDec::CT_RAW);
            pdu.information().eap() = eeap;
          }
          else TTCN_warning("Unsupported PPP message received with protocol :%x %x",stream_ptr[2],stream_ptr[3]);
      }  
      else
      {
        TTCN_warning("Unsupported PPP message received with protocol :%x %x",stream_ptr[2],stream_ptr[3]);
      }
    }
  
    
    if (stream.lengthof() == (lengthinfo + 4))
    {
      pdu.padding() = OMIT_VALUE;
    }
    else
    {
      pdu.padding() = substr(stream,(lengthinfo+4),stream.lengthof()-(lengthinfo+4));
    }
  }
  else
  {
    // decode PPP_BODY which starts at 0
   
    pdu.pPP__AddressControl() = OMIT_VALUE;

    pdu.protocol() = substr(stream,0,2);
    lengthinfo = oct2int(substr(stream,4,2));
    
    buf.put_os(substr(stream,2,lengthinfo));
    
    if  (stream_ptr[1] == 0x21) 
    {
      if (stream_ptr[0] == 0xc0)
      {
        elcp.decode(LCP_descr_, buf, TTCN_EncDec::CT_RAW);
        pdu.information().lcp() = elcp;
      }
      else
      {
        if (stream_ptr[0] == 0x80)
        {
          eipcp.decode(IPCP_descr_, buf, TTCN_EncDec::CT_RAW);
          pdu.information().ipcp() = eipcp;
        }
        else
        {
          if(stream_ptr[2] == 0x00)
          {
            eip4.decode(IP__Types::IPv4__packet_descr_, buf, TTCN_EncDec::CT_RAW);
            pdu.information().ip4() = eip4;          
          }
          else{
            TTCN_warning("Unsupported PPP message received with protocol :%x %x",stream_ptr[2],stream_ptr[3]);
          }
        }
      }
    }
    else
    {
      if (stream_ptr[1] == 0x23) 
      {
        if (stream_ptr[0] == 0xc2)
        {
          echap.decode(CHAP_descr_, buf, TTCN_EncDec::CT_RAW);
          pdu.information().chap() = echap;
        }
        else
        {
          if (stream_ptr[0] == 0xc0)
          {
            epap.decode(PAP_descr_, buf, TTCN_EncDec::CT_RAW);
            pdu.information().pap() = epap;
          }
          else
          {
            TTCN_warning("Unsupported PPP message received with protocol :%x  %x",stream_ptr[0],stream_ptr[1]); 
          }
        }
      }
      else if (stream_ptr[1] == 0x27) 
      {
        if (stream_ptr[0] == 0xc2)
          {
            eeap.decode(PDU__EAP_descr_, buf, TTCN_EncDec::CT_RAW);
            pdu.information().eap() = eeap;
          }
          else
          {
            TTCN_warning("Unsupported PPP message received with protocol :%x  %x",stream_ptr[0],stream_ptr[1]); 
          }
       }
      else
      {
        TTCN_warning("Unsupported PPP message received with protocol :%x  %x",stream_ptr[0],stream_ptr[1]);
      }
    }
    

    
    if (stream.lengthof() == (lengthinfo + 2))
    {
      pdu.padding() = OMIT_VALUE;
    }
    else
    {
      pdu.padding() = substr(stream,(lengthinfo+2),stream.lengthof()-(lengthinfo+2));
    }
  }

  return pdu;
}


}//namespace
