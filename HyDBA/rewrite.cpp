#include "vm.h"
#include <limits.h>
#include <intrin.h>
#include "asm.h"
#include "common.h"
#include "ept.h"
#include "log.h"
#include "util.h"
#include "vmm.h"
#include "performance.h"
#include "driver.h"
#include "int.h"

extern "C" {

extern ProcessorData  *processor_list[];
extern PVOID          *g_code_table;
extern PVOID          *g_entry_table;

extern ULONG   g_gdi32ExtTextOutW;
extern ULONG   g_notepad_7955;

extern ULONG   g_faultCodePage;
extern ULONG   g_checkCodePage;

extern PVOID __stdcall GetAllocBlockProfiler(ProcessorData *processorData, ULONG  faultIp);
extern unsigned int    DJBHash(char *str, unsigned int len);

USHORT  g_emuMovMemEaxTable[] = { 0x8089, 0x8889, 0x9089, 0x9889, 0xA089, 0xA889, 0xB089, 0xB889 };
USHORT  g_emuMovMemEbxTable[] = { 0x8389, 0x8B89, 0x9389, 0x9B89, 0xA389, 0xAB89, 0xB389, 0xBB89 };
USHORT  g_emuMovMemEdxTable[] = { 0x8289, 0x8A89, 0x9289, 0x9A89, 0xA289, 0xAA89, 0xB289, 0xBA89 };
ULONG   g_emuMovMemEspTable[] = { 0x248489, 0x248C89, 0x249489, 0x249C89, 
                                  0x24A489, 0x24AC89, 0x24B489, 0x24BC89 };


ULONG  g_emuMovRegEndInsTable[] = { 0xA164, 0, 0x158B64, 0x1D8B64, 0x258B64, 0, 0, 0 };
ULONG  g_emuMovRegEndLenTable[] = { 2, 0, 3, 3, 3, 0, 0, 0 };

ULONG  g_emuLeaEndTable[] = { 0x808D, 0, 0x928D, 0x9B8D, 0x24A48D, 0, 0, 0 };
ULONG  g_emuLeaEndLenTable[] = { 2, 0, 2, 2, 3, 0, 0, 0 };
ULONG  g_emuMovMemEndInsTable[] = { 0xA364, 0, 0x158964, 0x1D8964, 0x258964, 0, 0, 0 };
ULONG  g_emuMovMemEndLenTable[] = { 2, 0, 3, 3, 3, 0, 0, 0 };

//lea ecx, [ecx*2/4/8 + offset]  
ULONG g_leaEcxIndexOffTable[] = { 0x0D0C8D, 0x000000, 0x4D0C8D, 0x000000,
								  0x8D0C8D, 0x000000, 0x000000, 0x000000,
								  0xCD0C8D };
//lea ecx, [ecx + eax*2/4/8 + offset]  
ULONG g_leaEcxBaseIndexOffTable[] = { 0x00018C8D, 0x00018C8D, 0x00418C8D, 0x00000000,
							 0x00818C8D, 0x00000000, 0x00000000, 0x00000000,
							 0x00C18C8D };

UCHAR  g_emuCallJmpRetTemplReserved3[] = {
	0x8B,0xD1,                           //mov         edx,ecx
	0xC1,0xE9,0x0C,                      //shr         ecx,0Ch  
	0x81,0xE2,0xFF,0x0F,0x00,0x00,       //and         edx,0FFFh  
	0x8B,0x0C,0x8D,0x00,0x00,0x00,0x00,  //mov         ecx,dword ptr [ecx*4 + g_codeTable]  
	0x8B,0x0C,0x91,                      //mov         ecx,dword ptr [ecx + edx*4] 
	0x64,0x89,0x0D,0x68,0x00,0x00,0x00,  //mov         dword ptr fs:[68h],ecx
	//end
	0x04,0x7F,                           //add         al,7Fh
	0x9E,                                //sahf
	0x64,0x8B,0x15,0x7C,0x00,0x00,0x00,  //mov         edx,dword ptr fs:[7Ch] 
	0x64,0x8B,0x0D,0x78,0x00,0x00,0x00,  //mov         ecx,dword ptr fs:[78h]
	0x64,0xA1,0x70,0x00,0x00,0x00,       //mov         eax,dword ptr fs:[70h]
};

inline void memcpy_fast_16(void* dst, const void* src, size_t size)
{
	switch (size)
	{
	case 0: break;
	case 1: *(uint8_t*)dst = *(uint8_t*)src;
		break;
	case 2: *(uint16_t*)dst = *(uint16_t*)src;
		break;
	case 3:
		*(uint16_t*)dst = *(uint16_t*)src;
		*((uint8_t*)dst + 2) = *((uint8_t*)src + 2);
		break;
	case 4: *(uint32_t*)dst = *(uint32_t*)src;
		break;
	case 5:
		*(uint32_t*)dst = *(uint32_t*)src;
		*((uint8_t*)dst + 4) = *((uint8_t*)src + 4);
		break;
	case 6:
		*(uint32_t*)dst = *(uint32_t*)src;
		*(uint16_t*)((uint8_t*)dst + 4) = *(uint16_t*)((uint8_t*)src + 4);
		break;
	case 7:
		*(uint32_t*)dst = *(uint32_t*)src;
		*(uint32_t*)((uint8_t*)dst + 3) = *(uint32_t*)((uint8_t*)src + 3);
		break;
	case 8:
		*(uint64_t*)dst = *(uint64_t*)src;
		break;
	case 9:
		*(uint64_t*)dst = *(uint64_t*)src;
		*((uint8_t*)dst + 8) = *((uint8_t*)src + 8);
		break;
	case 10:
		*(uint64_t*)dst = *(uint64_t*)src;
		*(uint16_t*)((uint8_t*)dst + 8) = *(uint16_t*)((uint8_t*)src + 8);
		break;
	case 11:
		*(uint64_t*)dst = *(uint64_t*)src;
		*(uint32_t*)((uint8_t*)dst + 7) = *(uint32_t*)((uint8_t*)src + 7);
		break;
	case 12:
		*(uint64_t*)dst = *(uint64_t*)src;
		*(uint32_t*)((uint8_t*)dst + 8) = *(uint32_t*)((uint8_t*)src + 8);
		break;
	case 13:
		*(uint64_t*)dst = *(uint64_t*)src;
		*(uint64_t*)((uint8_t*)dst + 5) = *(uint64_t*)((uint8_t*)src + 5);
		break;
	case 14:
		*(uint64_t*)dst = *(uint64_t*)src;
		*(uint64_t*)((uint8_t*)dst + 6) = *(uint64_t*)((uint8_t*)src + 6);
		break;
	case 15:
		*(uint64_t*)dst = *(uint64_t*)src;
		*(uint64_t*)((uint8_t*)dst + 7) = *(uint64_t*)((uint8_t*)src + 7);
		break;
	default:
		memcpy(dst, src, size); break;
	}
}

UCHAR * __stdcall OpLoadRecordAddrGeneral(UCHAR *ptr, ud_t *pUdObj, ULONG oprIndx, ULONG recIndx)
{
	const  ud_operand_t* opr = &pUdObj->operand[oprIndx];
	ULONG  off = 0;

	switch (opr->offset)
	{
	case 8:
		off = (LONG)opr->lval.sbyte;
		break;
	case 16:
		off = (LONG)opr->lval.sword;
		break;
	case 32:
		off = opr->lval.sdword;
		break;
	default:
		break;
	}

	if (opr->base == UD_NONE) //base==0
	{
		if (opr->index == UD_NONE) //index==0; e.g. mov eax, [90h]
		{
			//mov  ecx,  90h
			*(UINT8 *)(ptr) = 0xB9;
			*(UINT32 *)(ptr + 1) = opr->lval.sdword;
			ptr += 5;
		}
		else  //index!=0; e.g. mov eax, [ecx*2/4/8];mov eax, [ecx*2/4/8 + 90h]£¬scale
		{
			*(UINT16 *)(ptr) = 0x8B8B;          //mov ecx, [ebx + 4*recIndx]
			*(UINT32 *)(ptr + 2) = (recIndx - 1) * 4; //lea ecx, [ecx*2/4/8 + offset]
			*(UINT32 *)(ptr + 6) = g_leaEcxIndexOffTable[opr->scale];
			*(UINT32 *)(ptr + 9) = off;
			ptr += 13;
		}
	}
	else  //base!=0
	{
		if (opr->index == UD_NONE) //index==0;  e.g. mov eax, [esp/ebp/edx + 90h]
		{
			*(UINT16 *)(ptr) = 0x8B8B;          //mov ecx, [ebx + 4*recIndx]
			*(UINT32 *)(ptr + 2) = (recIndx - 1) * 4;
			*(UINT16 *)(ptr + 6) = 0x898D;      //lea ecx, [ecx + offset]
			*(UINT32 *)(ptr + 8) = off;
			ptr += 12;
		}
		else  //index!=0; e.g. mov eax,[ebp+ecx/ebp+ecx+90h]
		{
			*(UINT16 *)(ptr) = 0x8B8B;          //mov ecx, [ebx + 4*recIndx]
			*(UINT32 *)(ptr + 2) = (recIndx - 2) * 4;
			*(UINT16 *)(ptr + 6) = 0x838B;      //mov eax, [ebx + 4*(recIndx+1)]
			*(UINT32 *)(ptr + 8) = (recIndx - 1) * 4;
			*(UINT32 *)(ptr + 12) = g_leaEcxBaseIndexOffTable[opr->scale]; //lea ecx, [ecx + eax*s + o]
			*(UINT32 *)(ptr + 15) = off;
			ptr += 19;
		}
	}

	return ptr;
}


UINT8 *OpAnalysisBuildIndirectJmp(UINT8 *code, ULONG count)
{
	*(UINT16 *)(code) = 0xC381;         //add  ebx, count*4 
	*(UINT32 *)(code + 2) = count * 4;
	*(UINT32 *)(code + 6) = 0x60FF038B; //mov  eax, [ebx]
	*(UINT8 *)(code + 10) = 0x1C;       //jmp  [eax + 1Ch]  //AnalysisCodePtr
	code += 11;

	return code;
}

UINT8 *OpAnalysisBuildJmpCode(UINT8 *code, ULONG count, OFFSET_SHADOW *offset, ULONG faultAddr)
{
	*(UINT16 *)(code) = 0xC381;                 //add  ebx, count * 4 
	*(UINT32 *)(code + 2) = count * 4;          
	*(UINT8 *)(code + 6) = 0xE9;                //jmp  NextAnalysisAddr
	*(UINT32 *)(code + 7) = (UINT32)faultAddr - ((UINT32)code + 6) - 5;
	offset->SbOffset1 = (UINT32)(code + 7);
	code += 11;

	return code;
}

UINT8 *OpAnalysisBuildJccCode(UINT8 *code, ULONG count, OFFSET_SHADOW *offset, ULONG faultAddr)
{
	*(UINT16 *)(code) = 0xC381;         //add  ebx, count*4 
	*(UINT32 *)(code + 2) = count * 4;  //mov  eax, [ebx]
	*(UINT32 *)(code + 6) = 0x3D038B;   //cmp  eax, NearProfiler
	*(UINT32 *)(code + 9) = faultAddr;
	offset->CompOffset2 = (UINT32)(code + 9);
	code += 13;
	*(UINT16 *)(code) = 0x850F;         //jne  FarAnalysisAddr
	*(UINT32 *)(code + 2) = faultAddr - (UINT32)code - 6;
	offset->SbOffset1 = (UINT32)(code + 2);
	*(UINT8 *)(code + 6) = 0xE9;        //jmp  NearAnalysisAddr
	*(UINT32 *)(code + 7) = faultAddr - (UINT32)(code + 6) - 5;
	offset->SbOffset2 = (UINT32)(code + 7);
	code += 11;

	return code;
}

UCHAR * _stdcall OpBlockEnd(UCHAR *codePtr, ULONG *recIndx, ULONG *recReg, UCHAR *cacheBase, UCHAR **pCachePtr)
{
	if ((*recReg) != UD_NONE)
	{
		ULONG reg = (*recReg) - UD_R_EAX;
		*(UINT32 *)(codePtr) = g_emuLeaEndTable[reg];           //lea  recReg, [recReg + 4*i]
		codePtr += g_emuLeaEndLenTable[reg];
		*(UINT32 *)(codePtr) = (*recIndx) * 4;
		*(UINT32 *)(codePtr + 4) = g_emuMovMemEndInsTable[reg]; //mov  fs:[1000h], recReg  
		codePtr = codePtr + 4 + g_emuMovMemEndLenTable[reg];
		*(UINT32 *)(codePtr) = 0x00001000;
		*(UINT32 *)(codePtr + 4) = g_emuMovRegEndInsTable[reg]; //mov  recReg,  fs:[74h]
		codePtr = codePtr + 4 + g_emuMovRegEndLenTable[reg];
		*(UINT32 *)(codePtr) = 0x00000074;
		codePtr += 4;
		*recReg = UD_NONE;
	}
	ULONG  cacheLen = (*pCachePtr) - cacheBase;
	if (cacheLen)
	{
		memcpy(codePtr, cacheBase, cacheLen);
		codePtr += cacheLen;
		*pCachePtr = cacheBase;
	}

	return codePtr;
}

UCHAR * _stdcall OpRecordJcc(UCHAR *codePtr, ULONG *recIndx, ULONG *recBlock, PVOID blockProfiler)
{
	if (!(*recBlock))
	{
		*recBlock = 1;
		*(UINT32 *)(codePtr) = 0x0074A364;       //mov  fs:[74h], eax
		*(UINT32 *)(codePtr + 4) = 0xA1640000;   //mov  eax, fs:[1000h]
		*(UINT32 *)(codePtr + 8) = 0x00001000;
		codePtr += 12;
		*(UINT16 *)(codePtr) = 0x80C7;           //mov  [eax + 4*i], profiler
		*(UINT32 *)(codePtr + 2) = (*recIndx) * 4;
		(*recIndx)++;
		*(UINT32 *)(codePtr + 6) = (ULONG)blockProfiler;
		*(UINT16 *)(codePtr + 10) = 0x808D;      //lea  eax, [eax + 4*(i+1)]
		*(UINT32 *)(codePtr + 12) = (*recIndx) * 4;
		*(UINT64 *)(codePtr + 16) = 0xA16400001000A364; //mov  fs:[1000h], eax
		*(UINT32 *)(codePtr + 24) = 0x00000074;  //mov  eax, fs:[74h]
		codePtr += 28;
	}

	return codePtr;
}

UCHAR * _stdcall OpRecordSysenter(UCHAR *codePtr, ULONG *recIndx, ULONG *recBlock, PVOID blockProfiler)
{
	*(UINT32 *)(codePtr) = 0x0074A364;       //mov  fs:[74h], eax
	*(UINT32 *)(codePtr + 4) = 0xA1640000;   //mov  eax, fs:[1000h]
	*(UINT32 *)(codePtr + 8) = 0x00001000;
	codePtr += 12;

	if (!(*recBlock))
	{
		*recBlock = 1;
		*(UINT16 *)(codePtr) = 0x80C7;       //mov  [eax + 4*i], profiler
		*(UINT32 *)(codePtr + 2) = (*recIndx) * 4;
		*(UINT32 *)(codePtr + 6) = (ULONG)blockProfiler;
		codePtr += 10;
		(*recIndx)++;
	}

	*(UINT16 *)(codePtr) = 0x80C7;           //mov  [eax + 4*(i+1)], profiler
	*(UINT32 *)(codePtr + 2) = (*recIndx) * 4;
	(*recIndx)++;
	*(UINT32 *)(codePtr + 6) = (ULONG)blockProfiler;
	*(UINT16 *)(codePtr + 10) = 0x808D;      //lea  eax, [eax + 4*(i+2)]
	*(UINT32 *)(codePtr + 12) = (*recIndx) * 4;
	*(UINT64 *)(codePtr + 16) = 0xA16400001000A364; //mov  fs:[1000h], eax
	*(UINT32 *)(codePtr + 24) = 0x00000074;         //mov  eax, fs:[74h]
	codePtr += 28;


	return codePtr;
}

UCHAR * _stdcall OpRecordRet(UCHAR *codePtr, ULONG *recIndx, ULONG *recBlock, PVOID blockProfiler)
{
	if (!(*recBlock))
	{
		*recBlock = 1;
		*(UINT64 *)(codePtr) = 0xC700001000158B64;    //mov edx, fs:[1000h]
		*(UINT8 *)(codePtr + 8) = 0x82;
		*(UINT32 *)(codePtr + 9) = 0x00000000;        //mov [edx + 0], blockProfiler
		*(UINT32 *)(codePtr + 13) = (ULONG)blockProfiler;
		*(UINT32 *)(codePtr + 17) = 0x6404528D;       //lea  edx, [edx + 4]
		*(UINT32 *)(codePtr + 21) = 0x10001589;       //mov  fs:[1000h], edx
		*(UINT16 *)(codePtr + 25) = 0x0000;
		codePtr += 27;
		(*recIndx)++;
	}
	return codePtr;
}

UCHAR *__stdcall OpRecordBlockAddr(UCHAR *codePtr, ud_operand_t* opr, ULONG *recIndx, ULONG *recReg,
	ULONG *recBlock, PVOID blockProfiler, UCHAR *cacheBase, UCHAR **pCachePtr)
{
	if ((opr->base == UD_NONE) && (opr->index == UD_NONE))
	{
		return codePtr;
	}
	//1
	if ((*recReg) != UD_NONE)
	{	
		ULONG reg = (*recReg) - UD_R_EAX;
		*(UINT32 *)(codePtr) = g_emuMovRegEndInsTable[reg]; //mov  recReg,  fs:[74h]
		codePtr += g_emuMovRegEndLenTable[reg];
		*(UINT32 *)(codePtr) = 0x00000074;
		codePtr += 4;
		*recReg = UD_NONE;
	}
	//2
	ULONG  cacheLen = (*pCachePtr) - cacheBase;
	if (cacheLen)
	{
		memcpy(codePtr, cacheBase, cacheLen);
		codePtr += cacheLen;
		*pCachePtr = cacheBase;
	}
	//3
	if ((opr->base != UD_NONE) && (opr->index != UD_NONE)) //base & index
	{
		if ((opr->base != UD_R_EAX) && (opr->index != UD_R_EAX))
		{
			*(UINT32 *)(codePtr)     = 0x0074A364;  //mov  fs:[74h], eax
			*(UINT32 *)(codePtr + 4) = 0xA1640000;  //mov  eax, fs:[1000h]
			*(UINT32 *)(codePtr + 8) = 0x00001000;
			codePtr += 12;
			if (!(*recBlock))
			{
				*recBlock = 1;
				*(UINT16 *)(codePtr) = 0x80C7;           //mov [eax + 4*i], profiler
				*(UINT32 *)(codePtr + 2) = (*recIndx) * 4;
				*(UINT32 *)(codePtr + 6) = (ULONG)blockProfiler;
				codePtr += 10;
				(*recIndx)++;
			}
			*(UINT16 *)(codePtr)     = g_emuMovMemEaxTable[opr->base - UD_R_EAX];
			*(UINT32 *)(codePtr + 2) = (*recIndx)*4;     //mov [eax + 4*i], base
			*(UINT16 *)(codePtr + 6) = g_emuMovMemEaxTable[opr->index - UD_R_EAX];
			*(UINT32 *)(codePtr + 8) = (*recIndx + 1)*4; //mov [eax + 4*(i+1)], index
			codePtr += 12;
			(*recIndx) += 2;
			*recReg = UD_R_EAX;
		}
		else if ((opr->base != UD_R_EBX) && (opr->index != UD_R_EBX))
		{
			*(UINT64 *)(codePtr)     = 0x64000000741D8964; //mov  fs:[74h], ebx
			*(UINT64 *)(codePtr + 8) = 0x000010001D8B;     //mov  ebx, fs:[1000h]
			codePtr += 14;
			if (!(*recBlock)) 
			{
				*recBlock = 1;
				*(UINT16 *)(codePtr) = 0x83C7;           //mov [ebx + 4*i], profiler
				*(UINT32 *)(codePtr + 2) = (*recIndx) * 4;
				*(UINT32 *)(codePtr + 6) = (ULONG)blockProfiler;
				codePtr += 10;
				(*recIndx)++;
			}
			*(UINT16 *)(codePtr) = g_emuMovMemEbxTable[opr->base - UD_R_EAX];
			*(UINT32 *)(codePtr + 2) = (*recIndx) * 4;     //mov [ebx + 4*i], base
			*(UINT16 *)(codePtr + 6) = g_emuMovMemEbxTable[opr->index - UD_R_EAX];
			*(UINT32 *)(codePtr + 8) = (*recIndx + 1) * 4; //mov [ebx + 4*(i+1)], index	
			codePtr += 12;
			(*recIndx) += 2;
			*recReg = UD_R_EBX;
		}
		else
		{
			*(UINT64 *)(codePtr) = 0x6400000074158964;  //mov  fs:[74h], edx
			*(UINT64 *)(codePtr + 8) = 0x00001000158B;  //mov  edx, fs:[1000h]
			codePtr += 14;
			if (!(*recBlock)) 
			{
				*recBlock = 1;
				*(UINT16 *)(codePtr) = 0x82C7;           //mov [edx + 4*i], profiler
				*(UINT32 *)(codePtr + 2) = (*recIndx) * 4;
				*(UINT32 *)(codePtr + 6) = (ULONG)blockProfiler;
				codePtr += 10;
				(*recIndx)++;
			}
			*(UINT16 *)(codePtr) = g_emuMovMemEdxTable[opr->base - UD_R_EAX];
			*(UINT32 *)(codePtr + 2) = (*recIndx) * 4;     //mov [edx + 4*i], base
			*(UINT16 *)(codePtr + 6) = g_emuMovMemEdxTable[opr->index - UD_R_EAX];
			*(UINT32 *)(codePtr + 8) = (*recIndx + 1) * 4; //mov [edx + 4*(i+1)], index	
			codePtr += 12;
			(*recIndx) += 2;
			*recReg = UD_R_EDX;
		}
	}
	else if (opr->base != UD_NONE)  //base
	{
		if (opr->base != UD_R_EAX)
		{
			*(UINT32 *)(codePtr) = 0x0074A364;      //mov  fs:[74h], eax
			*(UINT32 *)(codePtr + 4) = 0xA1640000;  //mov  eax, fs:[1000h]
			*(UINT32 *)(codePtr + 8) = 0x00001000;
			codePtr += 12;
			if (!(*recBlock)) 
			{
				*recBlock = 1;
				*(UINT16 *)(codePtr) = 0x80C7;           //mov [eax + 4*i], profiler
				*(UINT32 *)(codePtr + 2) = (*recIndx) * 4;
				*(UINT32 *)(codePtr + 6) = (ULONG)blockProfiler;
				codePtr += 10;
				(*recIndx)++;
			}
			*(UINT16 *)(codePtr) = g_emuMovMemEaxTable[opr->base - UD_R_EAX];
			*(UINT32 *)(codePtr + 2) = (*recIndx) * 4;   //mov [eax + 4*i], base
			codePtr += 6;
			(*recIndx)++;
			*recReg = UD_R_EAX;
		}
		else
		{
			*(UINT64 *)(codePtr) = 0x64000000741D8964;   //mov  fs:[74h], ebx
			*(UINT64 *)(codePtr + 8) = 0x000010001D8B;   //mov  ebx, fs:[1000h]
			codePtr += 14;
			if (!(*recBlock)) 
			{
				*recBlock = 1;
				*(UINT16 *)(codePtr) = 0x83C7;           //mov [ebx + 4*i], profiler
				*(UINT32 *)(codePtr + 2) = (*recIndx) * 4;
				*(UINT32 *)(codePtr + 6) = (ULONG)blockProfiler;
				codePtr += 10;
				(*recIndx)++;
			}
			*(UINT16 *)(codePtr) = g_emuMovMemEbxTable[opr->base - UD_R_EAX];
			*(UINT32 *)(codePtr + 2) = (*recIndx) * 4;     //mov [ebx + 4*i], base		
			codePtr += 6;
			(*recIndx)++;
			*recReg = UD_R_EBX;
		}
	}
	else if (opr->index != UD_NONE) //index
	{
		if (opr->index != UD_R_EAX)
		{
			*(UINT32 *)(codePtr) = 0x0074A364;      //mov  fs:[74h], eax
			*(UINT32 *)(codePtr + 4) = 0xA1640000;  //mov  eax, fs:[1000h]
			*(UINT32 *)(codePtr + 8) = 0x00001000;
			codePtr += 12;
			if (!(*recBlock))
			{
				*recBlock = 1;
				*(UINT16 *)(codePtr) = 0x80C7;           //mov [eax + 4*i], profiler
				*(UINT32 *)(codePtr + 2) = (*recIndx) * 4;
				*(UINT32 *)(codePtr + 6) = (ULONG)blockProfiler;
				codePtr += 10;
				(*recIndx)++;
			}
			*(UINT16 *)(codePtr) = g_emuMovMemEaxTable[opr->index - UD_R_EAX];
			*(UINT32 *)(codePtr + 2) = (*recIndx) * 4;   //mov [eax + 4*i], index
			codePtr += 6;
			(*recIndx)++;
			*recReg = UD_R_EAX;
		}
		else
		{
			*(UINT64 *)(codePtr) = 0x64000000741D8964;   //mov  fs:[74h], ebx
			*(UINT64 *)(codePtr + 8) = 0x000010001D8B;   //mov  ebx, fs:[1000h]
			codePtr += 14;
			if (!(*recBlock))
			{
				*recBlock = 1;
				*(UINT16 *)(codePtr) = 0x83C7;           //mov [ebx + 4*i], profiler
				*(UINT32 *)(codePtr + 2) = (*recIndx) * 4;
				*(UINT32 *)(codePtr + 6) = (ULONG)blockProfiler;
				codePtr += 10;
				(*recIndx)++;
			}
			*(UINT16 *)(codePtr) = g_emuMovMemEbxTable[opr->index - UD_R_EAX];
			*(UINT32 *)(codePtr + 2) = (*recIndx) * 4;   //mov [ebx + 4*i], index		
			codePtr += 6;
			(*recIndx)++;
			*recReg = UD_R_EBX;
		}
	}

	return codePtr;
}

UCHAR *__stdcall OpRecordBlockAddrEsp(UCHAR *codePtr, ud_operand_t* opr, ULONG *recIndx, ULONG *recReg,
	ULONG *recBlock, PVOID blockProfiler, UCHAR *cacheBase, UCHAR **pCachePtr)
{
	if ((*recReg) != UD_NONE)
	{
		ULONG reg = (*recReg) - UD_R_EAX;
		*(UINT32 *)(codePtr) = g_emuMovRegEndInsTable[reg]; //mov  recReg,  fs:[74h]
		codePtr += g_emuMovRegEndLenTable[reg];
		*(UINT32 *)(codePtr) = 0x00000074;
		codePtr += 4;
		(*recReg) = UD_NONE;
	}

	ULONG  cacheLen = (*pCachePtr) - cacheBase;
	if (cacheLen)
	{
		memcpy(codePtr, cacheBase, cacheLen);
		codePtr += cacheLen;
		*pCachePtr = cacheBase;
	}

	if ((opr->base != UD_NONE) && (opr->index != UD_NONE)) //base & index
	{
		if ((opr->base != UD_R_EAX) && (opr->index != UD_R_EAX))
		{
			*(UINT32 *)(codePtr) = 0x0074A364;      //mov  fs:[74h], eax
			*(UINT32 *)(codePtr + 4) = 0xA1640000;  //mov  eax, fs:[1000h]
			*(UINT32 *)(codePtr + 8) = 0x00001000;
			codePtr += 12;
			if (!(*recBlock))  
			{
				*recBlock = 1;
				*(UINT16 *)(codePtr) = 0x80C7;           //mov [eax + 4*i], profiler
				*(UINT32 *)(codePtr + 2) = (*recIndx) * 4;
				*(UINT32 *)(codePtr + 6) = (ULONG)blockProfiler;
				codePtr += 10;
				(*recIndx)++;
			}
			*(UINT16 *)(codePtr) = g_emuMovMemEaxTable[opr->base - UD_R_EAX];
			*(UINT32 *)(codePtr + 2) = (*recIndx) * 4;     //mov [eax + 4*i], base
			*(UINT16 *)(codePtr + 6) = g_emuMovMemEaxTable[opr->index - UD_R_EAX];
			*(UINT32 *)(codePtr + 8) = (*recIndx + 1) * 4; //mov [eax + 4*(i+1)], index
			*(UINT16 *)(codePtr + 12) = g_emuMovMemEaxTable[UD_R_ESP - UD_R_EAX];
			*(UINT32 *)(codePtr + 14) = (*recIndx + 2) * 4;  //mov [eax + 4*(i+2)], esp
			codePtr += 18;
			(*recIndx) += 3; 
			*recReg = UD_R_EAX;
		}
		else if ((opr->base != UD_R_EBX) && (opr->index != UD_R_EBX))
		{
			*(UINT64 *)(codePtr) = 0x64000000741D8964; //mov  fs:[74h], ebx
			*(UINT64 *)(codePtr + 8) = 0x000010001D8B;     //mov  ebx, fs:[1000h]
			codePtr += 14;
			if (!(*recBlock))   
			{
				*recBlock = 1;
				*(UINT16 *)(codePtr) = 0x83C7;           //mov [ebx + 4*i], profiler
				*(UINT32 *)(codePtr + 2) = (*recIndx) * 4;
				*(UINT32 *)(codePtr + 6) = (ULONG)blockProfiler;
				codePtr += 10;
				(*recIndx)++;
			}
			*(UINT16 *)(codePtr) = g_emuMovMemEbxTable[opr->base - UD_R_EAX];
			*(UINT32 *)(codePtr + 2) = (*recIndx) * 4;     //mov [ebx + 4*i], base
			*(UINT16 *)(codePtr + 6) = g_emuMovMemEbxTable[opr->index - UD_R_EAX];
			*(UINT32 *)(codePtr + 8) = (*recIndx + 1) * 4; //mov [ebx + 4*(i+1)], index	
			*(UINT16 *)(codePtr + 12) = g_emuMovMemEbxTable[UD_R_ESP - UD_R_EAX];
			*(UINT32 *)(codePtr + 14) = (*recIndx + 2) * 4;  //mov [ebx + 4*(i+2)], esp
			codePtr += 18;
			(*recIndx) += 3; 
			*recReg = UD_R_EBX;
		}
		else
		{
			*(UINT64 *)(codePtr) = 0x6400000074158964;  //mov  fs:[74h], edx
			*(UINT64 *)(codePtr + 8) = 0x00001000158B;  //mov  edx, fs:[1000h]
			codePtr += 14;
			if (!(*recBlock)) 
			{
				*recBlock = 1;
				*(UINT16 *)(codePtr) = 0x82C7;           //mov [edx + 4*i], profiler
				*(UINT32 *)(codePtr + 2) = (*recIndx) * 4;
				*(UINT32 *)(codePtr + 6) = (ULONG)blockProfiler;
				codePtr += 10;
				(*recIndx)++;
			}
			*(UINT16 *)(codePtr) = g_emuMovMemEdxTable[opr->base - UD_R_EAX];
			*(UINT32 *)(codePtr + 2) = (*recIndx) * 4;     //mov [edx + 4*i], base
			*(UINT16 *)(codePtr + 6) = g_emuMovMemEdxTable[opr->index - UD_R_EAX];
			*(UINT32 *)(codePtr + 8) = (*recIndx + 1) * 4; //mov [edx + 4*(i+1)], index	
			*(UINT16 *)(codePtr + 12) = g_emuMovMemEdxTable[UD_R_ESP - UD_R_EAX];
			*(UINT32 *)(codePtr + 14) = (*recIndx + 2) * 4;  //mov [edx + 4*(i+2)], esp
			codePtr += 18;
			(*recIndx) += 3;
			*recReg = UD_R_EDX;
		}
	}
	else if (opr->base != UD_NONE)  //base
	{
		if (opr->base != UD_R_EAX)
		{
			*(UINT32 *)(codePtr) = 0x0074A364;      //mov  fs:[74h], eax
			*(UINT32 *)(codePtr + 4) = 0xA1640000;  //mov  eax, fs:[1000h]
			*(UINT32 *)(codePtr + 8) = 0x00001000;
			codePtr += 12;
			if (!(*recBlock))
			{
				*recBlock = 1;
				*(UINT16 *)(codePtr) = 0x80C7;           //mov [eax + 4*i], profiler
				*(UINT32 *)(codePtr + 2) = (*recIndx) * 4;
				*(UINT32 *)(codePtr + 6) = (ULONG)blockProfiler;
				codePtr += 10;
				(*recIndx)++;
			}
			*(UINT16 *)(codePtr) = g_emuMovMemEaxTable[opr->base - UD_R_EAX];
			*(UINT32 *)(codePtr + 2) = (*recIndx) * 4;   //mov [eax + 4*i], base
			*(UINT16 *)(codePtr + 6) = g_emuMovMemEaxTable[UD_R_ESP - UD_R_EAX];
			*(UINT32 *)(codePtr + 8) = (*recIndx + 1) * 4;  //mov [eax + 4*(i+1)], esp
			codePtr += 12;
			(*recIndx) += 2;
			*recReg = UD_R_EAX;
		}
		else
		{
			*(UINT64 *)(codePtr) = 0x64000000741D8964;   //mov  fs:[74h], ebx
			*(UINT64 *)(codePtr + 8) = 0x000010001D8B;   //mov  ebx, fs:[1000h]
			codePtr += 14;
			if (!(*recBlock))
			{
				*recBlock = 1;
				*(UINT16 *)(codePtr) = 0x83C7;           //mov [ebx + 4*i], profiler
				*(UINT32 *)(codePtr + 2) = (*recIndx) * 4;
				*(UINT32 *)(codePtr + 6) = (ULONG)blockProfiler;
				codePtr += 10;
				(*recIndx)++;
			}
			*(UINT16 *)(codePtr) = g_emuMovMemEbxTable[opr->base - UD_R_EAX];
			*(UINT32 *)(codePtr + 2) = (*recIndx) * 4;     //mov [ebx + 4*i], base	
			*(UINT16 *)(codePtr + 6) = g_emuMovMemEbxTable[UD_R_ESP - UD_R_EAX];
			*(UINT32 *)(codePtr + 8) = (*recIndx + 1) * 4;  //mov [ebx + 4*(i+1)], esp
			codePtr += 12;
			(*recIndx) += 2;
			*recReg = UD_R_EBX;
		}
	}
	else if (opr->index != UD_NONE) //index
	{
		if (opr->index != UD_R_EAX)
		{
			*(UINT32 *)(codePtr) = 0x0074A364;      //mov  fs:[74h], eax
			*(UINT32 *)(codePtr + 4) = 0xA1640000;  //mov  eax, fs:[1000h]
			*(UINT32 *)(codePtr + 8) = 0x00001000;
			codePtr += 12;
			if (!(*recBlock))
			{
				*recBlock = 1;
				*(UINT16 *)(codePtr) = 0x80C7;           //mov [eax + 4*i], profiler
				*(UINT32 *)(codePtr + 2) = (*recIndx) * 4;
				*(UINT32 *)(codePtr + 6) = (ULONG)blockProfiler;
				codePtr += 10;
				(*recIndx)++;
			}
			*(UINT16 *)(codePtr) = g_emuMovMemEaxTable[opr->index - UD_R_EAX];
			*(UINT32 *)(codePtr + 2) = (*recIndx) * 4;   //mov [eax + 4*i], index
			*(UINT16 *)(codePtr + 6) = g_emuMovMemEaxTable[UD_R_ESP - UD_R_EAX];
			*(UINT32 *)(codePtr + 8) = (*recIndx + 1) * 4;  //mov [eax + 4*(i+1)], esp
			codePtr += 12;
			(*recIndx) += 2;
			*recReg = UD_R_EAX;
		}
		else
		{
			*(UINT64 *)(codePtr) = 0x64000000741D8964;   //mov  fs:[74h], ebx
			*(UINT64 *)(codePtr + 8) = 0x000010001D8B;   //mov  ebx, fs:[1000h]
			codePtr += 14;
			if (!(*recBlock))
			{
				*recBlock = 1;
				*(UINT16 *)(codePtr) = 0x83C7;           //mov [ebx + 4*i], profiler
				*(UINT32 *)(codePtr + 2) = (*recIndx) * 4;
				*(UINT32 *)(codePtr + 6) = (ULONG)blockProfiler;
				codePtr += 10;
				(*recIndx)++;
			}
			*(UINT16 *)(codePtr) = g_emuMovMemEbxTable[opr->index - UD_R_EAX];
			*(UINT32 *)(codePtr + 2) = (*recIndx) * 4;   //mov [ebx + 4*i], index	
			*(UINT16 *)(codePtr + 6) = g_emuMovMemEbxTable[UD_R_ESP - UD_R_EAX];
			*(UINT32 *)(codePtr + 8) = (*recIndx + 1) * 4;  //mov [ebx + 4*(i+1)], esp
			codePtr += 12;
			(*recIndx) += 2;
			*recReg = UD_R_EBX;
		}
	}
	else
	{
		*(UINT32 *)(codePtr) = 0x0074A364;      //mov  fs:[74h], eax
		*(UINT32 *)(codePtr + 4) = 0xA1640000;  //mov  eax, fs:[1000h]
		*(UINT32 *)(codePtr + 8) = 0x00001000;
		codePtr += 12;
		if (!(*recBlock)) 
		{
			*recBlock = 1;
			*(UINT16 *)(codePtr) = 0x80C7;           //mov [eax + 4*i], profiler
			*(UINT32 *)(codePtr + 2) = (*recIndx) * 4;
			*(UINT32 *)(codePtr + 6) = (ULONG)blockProfiler;
			codePtr += 10;
			(*recIndx)++;
		}
		*(UINT16 *)(codePtr) = g_emuMovMemEaxTable[UD_R_ESP - UD_R_EAX];
		*(UINT32 *)(codePtr + 2) = (*recIndx) * 4;  //mov [eax + 4*i], esp
		codePtr += 6;
		(*recIndx)++; 
		*recReg = UD_R_EAX;
	}

	return codePtr;
}

UCHAR *__stdcall OpRecordBlockAddrEflag(UCHAR *codePtr, ud_operand_t* opr, UCHAR opCode, ULONG *recIndx, ULONG *recReg,
	ULONG *recBlock, PVOID blockProfiler, UCHAR *cacheBase, UCHAR **pCachePtr)
{
	if ((*recReg) != UD_NONE)
	{
		ULONG reg = (*recReg) - UD_R_EAX;
		*(UINT32 *)(codePtr) = g_emuMovRegEndInsTable[reg]; //mov  recReg,  fs:[74h]
		codePtr += g_emuMovRegEndLenTable[reg];
		*(UINT32 *)(codePtr) = 0x00000074;
		codePtr += 4;
		(*recReg) = UD_NONE;
	}

	ULONG  cacheLen = (*pCachePtr) - cacheBase;
	if (cacheLen)
	{
		memcpy(codePtr, cacheBase, cacheLen);
		codePtr += cacheLen;
		*pCachePtr = cacheBase;
	}

	if ((opr->base != UD_NONE) && (opr->index != UD_NONE)) //base & index
	{
		if ((opr->base != UD_R_EAX) && (opr->index != UD_R_EAX))
		{
			*(UINT32 *)(codePtr) = 0x0074A364;      //mov  fs:[74h], eax
			*(UINT32 *)(codePtr + 4) = 0xA1640000;  //mov  eax, fs:[1000h]
			*(UINT32 *)(codePtr + 8) = 0x00001000;
			codePtr += 12;
			if (!(*recBlock))     
			{
				*recBlock = 1;
				*(UINT16 *)(codePtr) = 0x80C7;           //mov [eax + 4*i], profiler
				*(UINT32 *)(codePtr + 2) = (*recIndx) * 4;
				*(UINT32 *)(codePtr + 6) = (ULONG)blockProfiler;
				codePtr += 10;
				(*recIndx)++;
			}	
			*(UINT16 *)(codePtr) = g_emuMovMemEaxTable[opr->base - UD_R_EAX];
			*(UINT32 *)(codePtr + 2) = (*recIndx) * 4;  //mov [eax + 4*i], base
			*(UINT16 *)(codePtr + 6) = g_emuMovMemEaxTable[opr->index - UD_R_EAX];
			*(UINT32 *)(codePtr + 8) = (*recIndx + 1) * 4; //mov [eax + 4*(i+1)], index
			*(UINT8 *)(codePtr + 12) = 0x0F;
			*(UINT8 *)(codePtr + 13) = opCode;
			*(UINT8 *)(codePtr + 14) = 0x80;                //setcc byte ptr [eax + 4*(i+2)]
			*(UINT32 *)(codePtr + 15) = (*recIndx + 2) * 4;
			codePtr += 19;
			(*recIndx) += 3;  
			*recReg = UD_R_EAX;
		}
		else if ((opr->base != UD_R_EBX) && (opr->index != UD_R_EBX))
		{
			*(UINT64 *)(codePtr) = 0x64000000741D8964; //mov  fs:[74h], ebx
			*(UINT64 *)(codePtr + 8) = 0x000010001D8B;  //mov  ebx, fs:[1000h]
			codePtr += 14;
			if (!(*recBlock))  
			{
				*recBlock = 1;
				*(UINT16 *)(codePtr) = 0x83C7;           //mov [ebx + 4*i], profiler
				*(UINT32 *)(codePtr + 2) = (*recIndx) * 4;
				*(UINT32 *)(codePtr + 6) = (ULONG)blockProfiler;
				codePtr += 10;
				(*recIndx)++;
			}
			*(UINT16 *)(codePtr) = g_emuMovMemEbxTable[opr->base - UD_R_EAX];
			*(UINT32 *)(codePtr + 2) = (*recIndx) * 4; //mov [ebx + 4*(i)], base
			*(UINT16 *)(codePtr + 6) = g_emuMovMemEbxTable[opr->index - UD_R_EAX];
			*(UINT32 *)(codePtr + 8) = (*recIndx + 1) * 4; //mov [ebx + 4*(i+1)], index
			*(UINT8 *)(codePtr + 12) = 0x0F;
			*(UINT8 *)(codePtr + 13) = opCode;
			*(UINT8 *)(codePtr + 14) = 0x83;               //setcc byte ptr [ebx + 4*(i+2)]
			*(UINT32 *)(codePtr + 15) = (*recIndx + 2) * 4;
			codePtr += 19;
			(*recIndx) += 3; 
			*recReg = UD_R_EBX;
		}
		else
		{
			*(UINT64 *)(codePtr) = 0x6400000074158964;  //mov  fs:[74h], edx
			*(UINT64 *)(codePtr + 8) = 0x00001000158B;  //mov  edx, fs:[1000h]
			codePtr += 14;
			if (!(*recBlock)) 
			{
				*recBlock = 1;
				*(UINT16 *)(codePtr) = 0x82C7;           //mov [edx + 4*i], profiler
				*(UINT32 *)(codePtr + 2) = (*recIndx) * 4;
				*(UINT32 *)(codePtr + 6) = (ULONG)blockProfiler;
				codePtr += 10;
				(*recIndx)++;
			}		
			*(UINT16 *)(codePtr) = g_emuMovMemEdxTable[opr->base - UD_R_EAX];
			*(UINT32 *)(codePtr + 2) = (*recIndx) * 4; //mov [edx + 4*i], base
			*(UINT16 *)(codePtr + 6) = g_emuMovMemEdxTable[opr->index - UD_R_EAX];
			*(UINT32 *)(codePtr + 8) = (*recIndx + 1) * 4; //mov [edx + 4*(i+1)], index	
			*(UINT8 *)(codePtr + 12) = 0x0F;
			*(UINT8 *)(codePtr + 13) = opCode;
			*(UINT8 *)(codePtr + 14) = 0x82;               //setcc byte ptr [edx + 4*(i+2)]
			*(UINT32 *)(codePtr + 15) = (*recIndx + 2) * 4;
			codePtr += 19;
			(*recIndx) += 3; 
			*recReg = UD_R_EDX;
		}
	}
	else if (opr->base != UD_NONE)  //base
	{
		if (opr->base != UD_R_EAX)
		{
			*(UINT32 *)(codePtr) = 0x0074A364;      //mov  fs:[74h], eax
			*(UINT32 *)(codePtr + 4) = 0xA1640000;  //mov  eax, fs:[1000h]
			*(UINT32 *)(codePtr + 8) = 0x00001000;
			codePtr += 12;
			if (!(*recBlock))
			{
				*recBlock = 1;
				*(UINT16 *)(codePtr) = 0x80C7;           //mov [eax + 4*i], profiler
				*(UINT32 *)(codePtr + 2) = (*recIndx) * 4;
				*(UINT32 *)(codePtr + 6) = (ULONG)blockProfiler;
				codePtr += 10;
				(*recIndx)++;
			}
			*(UINT16 *)(codePtr) = g_emuMovMemEaxTable[opr->base - UD_R_EAX];
			*(UINT32 *)(codePtr + 2) = (*recIndx) * 4;  //mov [eax + 4*(i)], base	
			*(UINT8 *)(codePtr + 6) = 0x0F;
			*(UINT8 *)(codePtr + 7) = opCode;
			*(UINT8 *)(codePtr + 8) = 0x80;               //setcc byte ptr [eax + 4*(i+1)]
			*(UINT32 *)(codePtr + 9) = (*recIndx + 1) * 4;
			codePtr += 13;
			(*recIndx) += 2;
			*recReg = UD_R_EAX;
		}
		else
		{
			*(UINT64 *)(codePtr) = 0x64000000741D8964;   //mov  fs:[74h], ebx
			*(UINT64 *)(codePtr + 8) = 0x000010001D8B;   //mov  ebx, fs:[1000h]
			codePtr += 14;
			if (!(*recBlock))
			{
				*recBlock = 1;
				*(UINT16 *)(codePtr) = 0x83C7;           //mov [ebx + 4*i], profiler
				*(UINT32 *)(codePtr + 2) = (*recIndx) * 4;
				*(UINT32 *)(codePtr + 6) = (ULONG)blockProfiler;
				codePtr += 10;
				(*recIndx)++;
			}
			*(UINT16 *)(codePtr) = g_emuMovMemEbxTable[opr->base - UD_R_EAX];
			*(UINT32 *)(codePtr + 2) = (*recIndx) * 4; //mov [ebx + 4*(i)], base	
			*(UINT8 *)(codePtr + 6) = 0x0F;
			*(UINT8 *)(codePtr + 7) = opCode;
			*(UINT8 *)(codePtr + 8) = 0x83;               //setcc byte ptr [ebx + 4*(i + 1)]
			*(UINT32 *)(codePtr + 9) = (*recIndx + 1) * 4;
			codePtr += 13;
			(*recIndx) += 2;
			*recReg = UD_R_EBX;
		}
	}
	else if (opr->index != UD_NONE) //index
	{
		if (opr->index != UD_R_EAX)
		{
			*(UINT32 *)(codePtr) = 0x0074A364;      //mov  fs:[74h], eax
			*(UINT32 *)(codePtr + 4) = 0xA1640000;  //mov  eax, fs:[1000h]
			*(UINT32 *)(codePtr + 8) = 0x00001000;
			codePtr += 12;
			if (!(*recBlock))
			{
				*recBlock = 1;
				*(UINT16 *)(codePtr) = 0x80C7;           //mov [eax + 4*i], profiler
				*(UINT32 *)(codePtr + 2) = (*recIndx) * 4;
				*(UINT32 *)(codePtr + 6) = (ULONG)blockProfiler;
				codePtr += 10;
				(*recIndx)++;
			}
			*(UINT16 *)(codePtr) = g_emuMovMemEaxTable[opr->index - UD_R_EAX];
			*(UINT32 *)(codePtr + 2) = (*recIndx) * 4;   //mov [eax + 4*(i)], index	
			*(UINT8 *)(codePtr + 6) = 0x0F;
			*(UINT8 *)(codePtr + 7) = opCode;
			*(UINT8 *)(codePtr + 8) = 0x80;              //setcc byte ptr [eax + 4*(i+1)]
			*(UINT32 *)(codePtr + 9) = (*recIndx + 1) * 4;
			codePtr += 13;
			(*recIndx) += 2;
			*recReg = UD_R_EAX;
		}
		else
		{
			*(UINT64 *)(codePtr) = 0x64000000741D8964;   //mov  fs:[74h], ebx
			*(UINT64 *)(codePtr + 8) = 0x000010001D8B;   //mov  ebx, fs:[1000h]
			codePtr += 14;
			if (!(*recBlock))
			{
				*recBlock = 1;
				*(UINT16 *)(codePtr) = 0x83C7;           //mov [ebx + 4*i], profiler
				*(UINT32 *)(codePtr + 2) = (*recIndx) * 4;
				*(UINT32 *)(codePtr + 6) = (ULONG)blockProfiler;
				codePtr += 10;
				(*recIndx)++;
			}
			*(UINT16 *)(codePtr) = g_emuMovMemEbxTable[opr->index - UD_R_EAX];
			*(UINT32 *)(codePtr + 2) = (*recIndx) * 4;   //mov [ebx + 4*i], index
			*(UINT8 *)(codePtr + 6) = 0x0F;
			*(UINT8 *)(codePtr + 7) = opCode;
			*(UINT8 *)(codePtr + 8) = 0x83;               //setcc byte ptr [ebx + 4*(i+1)]
			*(UINT32 *)(codePtr + 9) = (*recIndx + 1) * 4;
			codePtr += 13;
			(*recIndx) += 2;
			*recReg = UD_R_EBX;
		}
	}
	else
	{
		*(UINT32 *)(codePtr) = 0x0074A364;      //mov  fs:[74h], eax
		*(UINT32 *)(codePtr + 4) = 0xA1640000;  //mov  eax, fs:[1000h]
		*(UINT32 *)(codePtr + 8) = 0x00001000;
		codePtr += 12;
		if (!(*recBlock))  
		{
			*recBlock = 1;
			*(UINT16 *)(codePtr) = 0x80C7;           //mov [eax + 4*i], profiler
			*(UINT32 *)(codePtr + 2) = (*recIndx) * 4;
			*(UINT32 *)(codePtr + 6) = (ULONG)blockProfiler;
			codePtr += 10;
			(*recIndx)++;
		}
		*(UINT8 *)(codePtr) = 0x0F;
		*(UINT8 *)(codePtr + 1) = opCode;
		*(UINT8 *)(codePtr + 2) = 0x80;              //setcc byte ptr [eax + 4*(i)]
		*(UINT32 *)(codePtr + 3) = (*recIndx) * 4;
		codePtr += 7;
		(*recIndx)++;
		*recReg = UD_R_EAX;
	}

	return codePtr;
}


UCHAR *__stdcall OpRecordBlockEsp(UCHAR *codePtr, ULONG *recIndx, ULONG *recReg,
	ULONG *recBlock, PVOID blockProfiler, UCHAR *cacheBase, UCHAR **pCachePtr)
{
	if ((*recReg) != UD_NONE)
	{
		ULONG reg = (*recReg) - UD_R_EAX;
		*(UINT32 *)(codePtr) = g_emuMovRegEndInsTable[reg]; //mov  recReg,  fs:[74h]
		codePtr += g_emuMovRegEndLenTable[reg];
		*(UINT32 *)(codePtr) = 0x00000074;
		codePtr += 4;
		(*recReg) = UD_NONE;
	}

	ULONG  cacheLen = (*pCachePtr) - cacheBase;
	if (cacheLen)
	{
		memcpy(codePtr, cacheBase, cacheLen);
		codePtr += cacheLen;
		*pCachePtr = cacheBase;
	}

	*(UINT32 *)(codePtr) = 0x0074A364;      //mov  fs:[74h], eax
	*(UINT32 *)(codePtr + 4) = 0xA1640000;  //mov  eax, fs:[1000h]
	*(UINT32 *)(codePtr + 8) = 0x00001000;
	codePtr += 12;
	if (!(*recBlock)) 
	{
		*recBlock = 1;
		*(UINT16 *)(codePtr) = 0x80C7;         //mov [eax + 4*i], profiler
		*(UINT32 *)(codePtr + 2) = (*recIndx) * 4;
		*(UINT32 *)(codePtr + 6) = (ULONG)blockProfiler;
		codePtr += 10;
		(*recIndx)++;
	}
	*(UINT16 *)(codePtr) = g_emuMovMemEaxTable[UD_R_ESP - UD_R_EAX];
	*(UINT32 *)(codePtr + 2) = (*recIndx) * 4;  //mov [eax + 4*i], esp
	codePtr += 6;
	(*recIndx)++;
	*recReg = UD_R_EAX;

	return codePtr;
}

UCHAR *__stdcall OpRecordBlockEflag(UCHAR *codePtr, UCHAR opCode, ULONG *recIndx, ULONG *recReg,
	ULONG *recBlock, PVOID blockProfiler, UCHAR *cacheBase, UCHAR **pCachePtr)
{
	if ((*recReg) != UD_NONE)
	{
		ULONG reg = (*recReg) - UD_R_EAX;
		*(UINT32 *)(codePtr) = g_emuMovRegEndInsTable[reg]; //mov  recReg,  fs:[74h]
		codePtr += g_emuMovRegEndLenTable[reg];
		*(UINT32 *)(codePtr) = 0x00000074;
		codePtr += 4;
		(*recReg) = UD_NONE;
	}

	ULONG  cacheLen = (*pCachePtr) - cacheBase;
	if (cacheLen)
	{
		memcpy(codePtr, cacheBase, cacheLen);
		codePtr += cacheLen;
		*pCachePtr = cacheBase;
	}

	*(UINT32 *)(codePtr) = 0x0074A364;      //mov  fs:[74h], eax
	*(UINT32 *)(codePtr + 4) = 0xA1640000;  //mov  eax, fs:[1000h]
	*(UINT32 *)(codePtr + 8) = 0x00001000;
	codePtr += 12;
	if (!(*recBlock))
	{
		*recBlock = 1;
		*(UINT16 *)(codePtr) = 0x80C7;      //mov [eax + 4*i], profiler
		*(UINT32 *)(codePtr + 2) = (*recIndx) * 4;
		*(UINT32 *)(codePtr + 6) = (ULONG)blockProfiler;
		codePtr += 10;
		(*recIndx)++;
	}
	//setcc
	*(UINT8 *)(codePtr) = 0x0F;
	*(UINT8 *)(codePtr + 1) = opCode;
	*(UINT8 *)(codePtr + 2) = 0x80;         //setcc byte ptr [eax + 4*i] 
	*(UINT32 *)(codePtr + 3) = (*recIndx) * 4;
	codePtr += 7;
	(*recIndx)++;     

	*recReg = UD_R_EAX;

	return codePtr;
}

UCHAR *__stdcall OpRecordBlockEsi(UCHAR *codePtr, ULONG *recIndx, ULONG *recReg,
	ULONG *recBlock, PVOID blockProfiler, UCHAR *cacheBase, UCHAR **pCachePtr)
{
	if ((*recReg) != UD_NONE)
	{
		ULONG reg = (*recReg) - UD_R_EAX;
		*(UINT32 *)(codePtr) = g_emuMovRegEndInsTable[reg]; //mov  recReg,  fs:[74h]
		codePtr += g_emuMovRegEndLenTable[reg];
		*(UINT32 *)(codePtr) = 0x00000074;
		codePtr += 4;
		(*recReg) = UD_NONE;
	}

	ULONG  cacheLen = (*pCachePtr) - cacheBase;
	if (cacheLen)
	{
		memcpy(codePtr, cacheBase, cacheLen);
		codePtr += cacheLen;
		*pCachePtr = cacheBase;
	}

	*(UINT32 *)(codePtr) = 0x0074A364;      //mov  fs:[74h], eax
	*(UINT32 *)(codePtr + 4) = 0xA1640000;  //mov  eax, fs:[1000h]
	*(UINT32 *)(codePtr + 8) = 0x00001000;
	codePtr += 12;
	if (!(*recBlock))    
	{
		*recBlock = 1;
		*(UINT16 *)(codePtr) = 0x80C7;         //mov [eax + 4*i], profiler
		*(UINT32 *)(codePtr + 2) = (*recIndx) * 4;
		*(UINT32 *)(codePtr + 6) = (ULONG)blockProfiler;
		codePtr += 10;
		(*recIndx)++;
	}
	*(UINT16 *)(codePtr) = g_emuMovMemEaxTable[UD_R_ESI - UD_R_EAX];
	*(UINT32 *)(codePtr + 2) = (*recIndx) * 4;  //mov [eax + 4*i], esi
	codePtr += 6;
	(*recIndx)++;    
	*recReg = UD_R_EAX;

	return codePtr;
}

UCHAR *__stdcall OpRecordBlockStos(UCHAR *codePtr, ULONG hasRep, ULONG *recIndx, ULONG *recReg,
	ULONG *recBlock, PVOID blockProfiler, UCHAR *cacheBase, UCHAR **pCachePtr)
{
	if ((*recReg) != UD_NONE)
	{
		ULONG reg = (*recReg) - UD_R_EAX;
		*(UINT32 *)(codePtr) = g_emuMovRegEndInsTable[reg]; //mov  recReg,  fs:[74h]
		codePtr += g_emuMovRegEndLenTable[reg];
		*(UINT32 *)(codePtr) = 0x00000074;
		codePtr += 4;
		(*recReg) = UD_NONE;
	}

	ULONG  cacheLen = (*pCachePtr) - cacheBase;
	if (cacheLen)
	{
		memcpy(codePtr, cacheBase, cacheLen);
		codePtr += cacheLen;
		*pCachePtr = cacheBase;
	}

	*(UINT64 *)(codePtr) = 0x6400000074258964;   //mov  fs:[74h], esp
	*(UINT64 *)(codePtr + 8) = 0x00001000258B;   //mov  esp, fs:[1000h]
	codePtr += 14;
	if (!(*recBlock))
	{
		*recBlock = 1;
		*(UINT32 *)(codePtr) = 0x2484C7;          //mov [esp + 4*i], profiler
		*(UINT32 *)(codePtr + 3) = (*recIndx) * 4;
		*(UINT32 *)(codePtr + 7) = (ULONG)blockProfiler;
		codePtr += 11;
		(*recIndx)++;
	}

	*(UINT32 *)(codePtr) = g_emuMovMemEspTable[UD_R_EDI - UD_R_EAX];
	*(UINT32 *)(codePtr + 3) = (*recIndx) * 4; //mov  [esp + 4*(i)], edi 
	codePtr += 7;
	(*recIndx)++;

	if (hasRep)
	{
		//eflags¡¢ecx
		*(UINT32 *)(codePtr) = 0x24A48D;                //lea  esp, [esp + 4*(i+1)]
		*(UINT32 *)(codePtr + 3) = (*recIndx + 1) * 4;  //pushfd; 
		*(UINT32 *)(codePtr + 7) = 0x24A48D9C;          //lea  esp, [esp - 4*i]; 
		*(UINT32 *)(codePtr + 11) = 0xFFFFFFFF - (*recIndx) * 4 + 1;
		*(UINT32 *)(codePtr + 15) = g_emuMovMemEspTable[UD_R_ECX - UD_R_EAX];
		*(UINT32 *)(codePtr + 18) = (*recIndx + 1) * 4;  //mov [esp + 4*i], ecx 
		codePtr += 22;
		(*recIndx) += 2;
	}

	*recReg = UD_R_ESP;

	return codePtr;
}

UCHAR *__stdcall OpRecordBlockMovs(UCHAR *codePtr, ULONG hasRep, ULONG *recIndx, ULONG *recReg,
	ULONG *recBlock, PVOID blockProfiler, UCHAR *cacheBase, UCHAR **pCachePtr)
{
	if ((*recReg) != UD_NONE)
	{
		ULONG reg = (*recReg) - UD_R_EAX;
		*(UINT32 *)(codePtr) = g_emuMovRegEndInsTable[reg]; //mov  recReg,  fs:[74h]
		codePtr += g_emuMovRegEndLenTable[reg];
		*(UINT32 *)(codePtr) = 0x00000074;
		codePtr += 4;
		(*recReg) = UD_NONE;
	}

	ULONG  cacheLen = (*pCachePtr) - cacheBase;
	if (cacheLen)
	{
		memcpy(codePtr, cacheBase, cacheLen);
		codePtr += cacheLen;
		*pCachePtr = cacheBase;
	}

	*(UINT64 *)(codePtr) = 0x6400000074258964;   //mov  fs:[74h],  esp
	*(UINT64 *)(codePtr + 8) = 0x00001000258B;   //mov  esp,  fs:[1000h]
	codePtr += 14;
	if (!(*recBlock))
	{
		*recBlock = 1;
		*(UINT32 *)(codePtr) = 0x2484C7;          //mov [esp + 4*i], profiler
		*(UINT32 *)(codePtr + 3) = (*recIndx) * 4;
		*(UINT32 *)(codePtr + 7) = (ULONG)blockProfiler;
		codePtr += 11;
		(*recIndx)++;
	}
	//esi¡¢edi
	*(UINT32 *)(codePtr) = g_emuMovMemEspTable[UD_R_ESI - UD_R_EAX];
	*(UINT32 *)(codePtr + 3) = (*recIndx) * 4;      //mov [esp + 4*(i)], esi 
	*(UINT32 *)(codePtr + 7) = g_emuMovMemEspTable[UD_R_EDI - UD_R_EAX];
	*(UINT32 *)(codePtr + 10) = (*recIndx + 1) * 4; //mov [esp + 4*(i+1)], edi
	codePtr += 14;
	(*recIndx) += 2;
	if (hasRep)
	{
		//eflags£¬ecx
		*(UINT32 *)(codePtr) = 0x24A48D;               //lea  esp, [esp + 4*(i+1)]
		*(UINT32 *)(codePtr + 3) = (*recIndx + 1) * 4; //pushfd
		*(UINT32 *)(codePtr + 7) = 0x24A48D9C;         //lea  esp, [esp - 4*i];
		*(UINT32 *)(codePtr + 11) = 0xFFFFFFFF - (*recIndx) * 4 + 1;
		*(UINT32 *)(codePtr + 15) = g_emuMovMemEspTable[UD_R_ECX - UD_R_EAX];
		*(UINT32 *)(codePtr + 18) = (*recIndx + 1) * 4;  //mov [esp + 4*(i+1)], ecx 
		codePtr += 22;
		(*recIndx) += 2;
	}
	*recReg = UD_R_ESP;

	return codePtr;
}

void __stdcall ParseBuildBlockLinkRecord(ProcessorData *processorData, BLOCK_PROFILER *blockProfiler, ULONG faultIp)
{
	ud_t   *p_ud = &processorData->ud_obj;
	const   ud_operand_t* opr0 = &p_ud->operand[0];
	const   ud_operand_t* opr1 = &p_ud->operand[1];
	const   ud_operand_t* opr2 = &p_ud->operand[2];
	
	ULONG   farAddr = 0;
	ULONG   nearAddr = 0;
	ULONG   disLen = 0;
	ULONG   insCount = 0;
	UCHAR   bh0, bi0, bh1, bi1;

	ULONG recIndex = 0;
	ULONG recReg = UD_NONE;
	ULONG recBlock = 0;

	//Execution code
	UCHAR   *codePtr = (UCHAR *)processorData->buf_ptr;
	UCHAR   *codeBase = codePtr;
	ULONG    curIp = faultIp;

	UCHAR   *cacheBase = (UCHAR *)processorData->tmpbuf_ptr;
	UCHAR   *cachePtr = cacheBase;
	//Analysis code
	UCHAR   *shadowPtr = (UCHAR *)processorData->asbuf_ptr;
	UCHAR   *analysisBase = shadowPtr;

	ULONG         localBranchOffset1 = 0;  //far
	ULONG         localBranchOffset2 = 0;
	OFFSET_SHADOW localSbOffset = { 0 };

	if ((codePtr + 0x1000) > (UCHAR *)(processorData->buf_base + PER_CPU_CODE_BUF_SIZE))
	{
		DbgPrint("[CHECK] BufBase %x, codePtr %x\n", processorData->buf_base, codePtr);
		__debugbreak();
		ZwTerminateProcess(NtCurrentProcess(), 1);
	}
	if ((shadowPtr + 0x100) > (UCHAR *)(processorData->asbuf_base + PER_CPU_ANALYSIS_BUF_SIZE))
	{
		DbgPrint("[CHECK] asbuf_base %x, asbuf_ptr %x\n", processorData->asbuf_base, processorData->asbuf_ptr);
		HYPERPLATFORM_COMMON_DBG_BREAK();
	}

	//nop word ptr [eax + eax + PROFILER]
	*(UINT32 *)(codePtr) = 0x841F0F66;
	*(UINT8 *)(codePtr + 4) = 0x00;
	*(UINT32 *)(codePtr + 5) = (UINT32)blockProfiler; //+5
	codePtr += 9;
	//[DEBUG]£ºmov fs:[1008h], pBlockProfiler
	/**(UINT32 *)(codePtr) = 0x0805C764;
	*(UINT32 *)(codePtr + 4) = 0x000010;
	*(UINT32 *)(codePtr + 7) = (UINT32)blockProfiler;
	codePtr += 11;*/
	//[DEBUG]£ºxmm0
	//*(UINT8 *)shadowPtr = 0xB8;       //mov eax, blockProfiler
	//*(UINT32 *)(shadowPtr + 1) = (UINT32)blockProfiler;
	//*(UINT32 *)(shadowPtr + 5) = 0xC06E0F66; //mov xmm0, eax
	//*(UINT8 *)(shadowPtr + 9) = 0xC3; //ret
	//shadowPtr += 9;
	*(UINT32 *)(shadowPtr) = 0x3042C7;       //mov  [edx + 30h], blockProfiler
	*(UINT32 *)(shadowPtr + 3) = (UINT32)blockProfiler;
	*(UINT32 *)(shadowPtr + 7) = 0x89345A89; //mov  [edx + 34h], ebx
	*(UINT32 *)(shadowPtr + 11) = 0xC3386A;  //mov  [edx + 38h], ebp
	shadowPtr += 13;

	//Check at block level£¬if count is large£¬the instruction level can be used
	*(UINT16 *)(shadowPtr) = 0x838D;         //lea   eax, [ebx + count*4]
	*(UINT32 *)(shadowPtr + 2) = 0x10000000; //cmp   eax, ebp
	*(UINT32 *)(shadowPtr + 6) = 0x0572C53B; //jb    CONTINUE
	*(UINT8 *)(shadowPtr + 10) = 0xE8;       //call  AsmAnalysisCheckStub
	*(UINT32 *)(shadowPtr + 11) = (UINT32)AsmAnalysisCheckStub - ((UINT32)shadowPtr + 10) - 5;
	UCHAR  *countPtr = shadowPtr + 2;
	shadowPtr += 15;

	//Special handler
	//if (curIp == g_gdi32ExtTextOutW)
	//{
	//	*(UINT8 *)(codePtr) = 0xA1;          //mov  eax, [g_checkCodePage + 0x100];
	//	*(UINT32 *)(codePtr + 1) = g_checkCodePage + 0x100;
	//	codePtr += 5;
	//	*(UINT8 *)(shadowPtr) = 0xB8;        //mov  eax, g_checkCodePage
	//	*(UINT32 *)(shadowPtr + 1) = g_checkCodePage;
	//	*(UINT16 *)(shadowPtr + 5) = 0x008B; //mov  eax, [eax]
	//	shadowPtr += 7;
	//}
	//if (curIp == g_notepad_7955)
	//{
	//	*(UINT8 *)(codePtr) = 0xA1;          //mov  eax, [g_checkCodePage + 0x100];
	//	*(UINT32 *)(codePtr + 1) = g_checkCodePage + 0x100;
	//	codePtr += 5;
	//	*(UINT8 *)(shadowPtr) = 0xB8;        //mov  eax, g_checkCodePage
	//	*(UINT32 *)(shadowPtr + 1) = g_checkCodePage;
	//	*(UINT16 *)(shadowPtr + 5) = 0x008B; //mov  eax, [eax]
	//	shadowPtr += 7;
	//}

	ud_set_input_buffer(p_ud, (uint8_t *)curIp, 2 * PAGE_SIZE); 
	while (true)
	{
		insCount++;
		//#PF
		disLen = ud_decode(p_ud);
		//Many bugs of udis86
		if (p_ud->mnemonic == UD_Ivpsllq)
		{
			if (*(UCHAR *)(curIp + 2) == 0x73) //vpsllq  xmm2,xmm4,2Ah
			{
				disLen = 5;
				memcpy_fast_16(cachePtr, (void *)curIp, disLen);
				cachePtr += disLen;
				curIp += disLen;
				blockProfiler->BlockSize += disLen;
				ud_set_input_buffer(p_ud, (uint8_t *)curIp, 4 * PAGE_SIZE);
				continue;
			}
		}
		if (!disLen || (p_ud->mnemonic == UD_Iinvalid))
		{
			DbgPrint("[CHECK] Decode error. disLen %d, mnemonic %d, faultIp %x, profiler %x, start %x, curIp %x, codePtr %x\n",
				disLen, p_ud->mnemonic, faultIp, blockProfiler, processorData->dis_ip, curIp, codePtr);
			if ((*(USHORT *)curIp == 0xfdc5) || //pscp: vpmovmskb eax,ymm0
				(*(USHORT *)curIp == 0xf5c5))  //vpcmpeqb ymm0,ymm1,ymmword ptr [ecx]
			{
				disLen = 4;
				memcpy_fast_16(cachePtr, (void *)curIp, disLen);
				cachePtr += disLen;
				curIp += disLen;
				blockProfiler->BlockSize += disLen;
				ud_set_input_buffer(p_ud, (uint8_t *)curIp, 4 * PAGE_SIZE);
				continue;
			}
			else if (*(USHORT *)curIp == 0xe3c4) //xz_r: vinserti128 ymm7,ymm0,xmm1,0
			{
				disLen = 6;
				memcpy_fast_16(cachePtr, (void *)curIp, disLen);
				cachePtr += disLen;
				curIp += disLen;
				blockProfiler->BlockSize += disLen;
				ud_set_input_buffer(p_ud, (uint8_t *)curIp, 4 * PAGE_SIZE);
				continue;
			}
			else if (*(USHORT *)curIp == 0xe5c5) //xz_r: vpslld  ymm0,ymm3,xmm7
			{
				disLen = 4;
				if (*(USHORT *)(curIp + 2) == 0x0ddb) //vpand   ymm1,ymm3,ymmword ptr ds:[xxxx]
				{
					disLen = 8;
				}
				memcpy_fast_16(cachePtr, (void *)curIp, disLen);
				cachePtr += disLen;
				curIp += disLen;
				blockProfiler->BlockSize += disLen;
				ud_set_input_buffer(p_ud, (uint8_t *)curIp, 4 * PAGE_SIZE);
				continue;
			}
			else if (*(USHORT *)curIp == 0xfdc5) //xz_r:   vpslld  ymm2,ymm0,xmm5
			{                                    //x264_r: vpmovmskb eax, ymm0
				disLen = 4;
				memcpy_fast_16(cachePtr, (void *)curIp, disLen);
				cachePtr += disLen;
				curIp += disLen;
				blockProfiler->BlockSize += disLen;
				ud_set_input_buffer(p_ud, (uint8_t *)curIp, 4 * PAGE_SIZE);
				continue;
			}
			else if (*(USHORT *)curIp == 0xe2c4) //perlbench_r: shlx ecx,edx,ebx; blsr eax,edi
			{
				disLen = 5; //andn  eax,eax,ecx
				if (*(USHORT *)(curIp + 4) == 0x2484)     //shlx eax,[esp+800000h],eax
				{
					disLen = 10;
				}
				else if (*(USHORT *)(curIp + 4) == 0x2444) //shlx eax,[esp+40h],eax
				{
					disLen = 7;
				}
				else if (*(USHORT *)(curIp + 4) == 0x2464) //vpbroadcastd ymm4,dword ptr [esp+48h]
				{
					disLen = 7;
				}
				else if (*(USHORT *)(curIp + 2) == 0x5979) //vpbroadcastq xmm0,mmword ptr ds:[0EF4ED8h]
				{
					disLen = 9;
				}
				else if (*(USHORT *)(curIp + 3) == 0x1c58) //vpbroadcastd ymm3,dword ptr [ecx+eax]
				{
					disLen = 6;
				}
				else if ((*(USHORT *)(curIp + 3) == 0x80f7) || //sarx  eax, dword ptr[eax + 64000440h], ecx
					(*(USHORT *)(curIp + 3) == 0x86f7) || //x264_r: shlx eax,dword ptr [esi+28C0h],eax
					(*(USHORT *)(curIp + 3) == 0x87f7) || //        shlx eax,dword ptr [edi+28C0h],ecx
					(*(USHORT *)(curIp + 3) == 0x8af7) || //xz_r: sarx  ecx,dword ptr [edx+494h],eax
					(*(USHORT *)(curIp + 3) == 0x96f7))   //xz_r: shrx  edx,dword ptr [esi+134h],eax
				{
					disLen = 9;
				}
				else if ((*(USHORT *)(curIp + 3) == 0x4cf7) || //xz_r: 
					(*(USHORT *)(curIp + 3) == 0x44f7))   //x264_r: shlx eax,dword ptr [esp+28h],esi
				{
					disLen = 7;
				}
				else if ((*(USHORT *)(curIp + 3) == 0x42f7) ||  //x264_r: sarx  eax,dword ptr [edx+18h],eax
					(*(USHORT *)(curIp + 3) == 0x46f7) || //x264_r: sarx eax,dword ptr [esi+18h],edx
					(*(USHORT *)(curIp + 3) == 0x47f7) || //x264_r: shlx  eax,dword ptr [edi+0Ch],ebx
					(*(USHORT *)(curIp + 3) == 0x4ff7) || //x264_r: shlx  ecx,dword ptr [edi+0Ch],eax
					(*(USHORT *)(curIp + 3) == 0x52f7) || //x264_r: sarx  edx,dword ptr [edx+14h],eax
					(*(USHORT *)(curIp + 3) == 0x56f7) ||    //x264_r: shlx  edx,dword ptr [esi+0Ch],edi
					(*(USHORT *)(curIp + 3) == 0x77f7) || //shlx    esi,dword ptr [edi+64h],ecx
					(*(USHORT *)(curIp + 3) == 0x04f7) || //shlx    eax,dword ptr [ecx+edx],edi
					(*(USHORT *)(curIp + 3) == 0x0cf7) || //shlx    ecx,dword ptr [ecx+eax],edi
					(*(USHORT *)(curIp + 3) == 0x14f7)    //shlx    edx,dword ptr [esi+eax],ecx
					)
				{
					disLen = 6;
				}
				memcpy_fast_16(cachePtr, (void *)curIp, disLen);
				cachePtr += disLen;
				curIp += disLen;
				blockProfiler->BlockSize += disLen;
				ud_set_input_buffer(p_ud, (uint8_t *)curIp, 4 * PAGE_SIZE);
				continue;
			}
			else
			{
				DbgPrint("[CHECK] Decode error. disLen %d, mnemonic %d, faultIp %x, profiler %x, start %x, curIp %x\n",
					disLen, p_ud->mnemonic, faultIp, blockProfiler, processorData->dis_ip, curIp);
				HYPERPLATFORM_COMMON_DBG_BREAK();
			}
		}
		blockProfiler->BlockSize += disLen;

		if (opr0->type == UD_OP_JIMM) //jcc/jmp rel;call rel32
		{
			codePtr = OpBlockEnd(codePtr, &recIndex, &recReg, cacheBase, &cachePtr);
			codePtr = OpRecordJcc(codePtr, &recIndex, &recBlock, blockProfiler);
			switch (opr0->size)
			{
			case 8:
				farAddr = curIp + opr0->lval.sbyte + disLen; 
				nearAddr = curIp + disLen;
				break;
			case 16:
				farAddr = curIp + opr0->lval.sword + disLen;
				nearAddr = curIp + disLen;
				break;
			case 32:
				farAddr = curIp + opr0->lval.sdword + disLen;
				nearAddr = curIp + disLen;
				break;
			default:
				__debugbreak();
			}
			switch (p_ud->mnemonic)
			{
			case UD_Icall:           //far call, retf
				*codePtr = 0x68;
				*(UINT32 *)(codePtr + 1) = nearAddr; //push nearAddr
				codePtr += 5;
				*(UINT8 *)codePtr = 0xE9;            //jmp  farAddr	
				*(UINT32 *)(codePtr + 1) = farAddr - (UINT32)codePtr - 5;
				localBranchOffset1 = (ULONG)(codePtr + 1);
				localBranchOffset2 = 0;
				codePtr += 5;
				shadowPtr = OpAnalysisBuildJmpCode(shadowPtr, recIndex, &localSbOffset, g_faultCodePage);
				break;
			case UD_Ijmp:
				*(UINT8 *)codePtr = 0xE9;            //jmp  farAddr 
				*(UINT32 *)(codePtr + 1) = farAddr - (UINT32)codePtr - 5;
				localBranchOffset1 = (ULONG)(codePtr + 1);
				localBranchOffset2 = 0;
				codePtr += 5;
				shadowPtr = OpAnalysisBuildJmpCode(shadowPtr, recIndex, &localSbOffset, g_faultCodePage + 4);
				break;
			case UD_Ijecxz:   //ecx = 0
				*(UINT16 *)codePtr = 0x05E3;
				*(UINT8 *)(codePtr + 2) = 0xE9;
				*(UINT32 *)(codePtr + 3) = nearAddr - (UINT32)(codePtr + 2) - 5;
				localBranchOffset2 = (ULONG)(codePtr + 3);
				*(UINT8 *)(codePtr + 7) = 0xE9;
				*(UINT32 *)(codePtr + 8) = farAddr - (UINT32)(codePtr + 7) - 5;
				localBranchOffset1 = (ULONG)(codePtr + 8);
				codePtr += 12;
				DbgPrint("[INFO] decode UD_Ijecxz type %x, curIp %x\n", p_ud->mnemonic, curIp);
				shadowPtr = OpAnalysisBuildJccCode(shadowPtr, recIndex, &localSbOffset, g_faultCodePage + 8);
				break;
			case UD_Ijo:    //of = 1, 0f 80
				*(UINT16 *)codePtr = 0x800F;        //jcc  farAddr
				*(UINT32 *)(codePtr + 2) = farAddr - (UINT32)codePtr - 6;
				localBranchOffset1 = (ULONG)(codePtr + 2);
				*(UINT8 *)(codePtr + 6) = 0xE9;    //jmp  nearAddr
				*(UINT32 *)(codePtr + 7) = nearAddr - (UINT32)(codePtr + 6) - 5;
				localBranchOffset2 = (ULONG)(codePtr + 7);
				codePtr += 11;
				shadowPtr = OpAnalysisBuildJccCode(shadowPtr, recIndex, &localSbOffset, g_faultCodePage + 12);
				break;
			case UD_Ijno:   //of = 0, 0f 81
				*(UINT16 *)codePtr = 0x810F;        //jcc  farAddr
				*(UINT32 *)(codePtr + 2) = farAddr - (UINT32)codePtr - 6;
				localBranchOffset1 = (ULONG)(codePtr + 2);
				*(UINT8 *)(codePtr + 6) = 0xE9;    //jmp  nearAddr
				*(UINT32 *)(codePtr + 7) = nearAddr - (UINT32)(codePtr + 6) - 5;
				localBranchOffset2 = (ULONG)(codePtr + 7);
				codePtr += 11;
				shadowPtr = OpAnalysisBuildJccCode(shadowPtr, recIndex, &localSbOffset, g_faultCodePage + 16);
				break;	
			case UD_Ijb:   //cf = 1 , jc, jnae 0f 82
				*(UINT16 *)codePtr = 0x820F;        //jcc  farAddr
				*(UINT32 *)(codePtr + 2) = farAddr - (UINT32)codePtr - 6;
				localBranchOffset1 = (ULONG)(codePtr + 2);
				*(UINT8 *)(codePtr + 6) = 0xE9;     //jmp  nearAddr
				*(UINT32 *)(codePtr + 7) = nearAddr - (UINT32)(codePtr + 6) - 5;
				localBranchOffset2 = (ULONG)(codePtr + 7);
				codePtr += 11;
				shadowPtr = OpAnalysisBuildJccCode(shadowPtr, recIndex, &localSbOffset, g_faultCodePage + 20);
				break;
			case UD_Ijae:  //cf = 0, jnb,jnc 0f 83
				*(UINT16 *)codePtr = 0x830F;        //jcc  farAddr
				*(UINT32 *)(codePtr + 2) = farAddr - (UINT32)codePtr - 6;
				localBranchOffset1 = (ULONG)(codePtr + 2);
				*(UINT8 *)(codePtr + 6) = 0xE9;    //jmp  nearAddr
				*(UINT32 *)(codePtr + 7) = nearAddr - (UINT32)(codePtr + 6) - 5;
				localBranchOffset2 = (ULONG)(codePtr + 7);
				codePtr += 11;
				shadowPtr = OpAnalysisBuildJccCode(shadowPtr, recIndex, &localSbOffset, g_faultCodePage + 24);
				break;
			case UD_Ijz: //zf = 1, je, 0f 84
				*(UINT16 *)codePtr = 0x840F;        //jcc  farAddr
				*(UINT32 *)(codePtr + 2) = farAddr - (UINT32)codePtr - 6;
				localBranchOffset1 = (ULONG)(codePtr + 2);
				*(UINT8 *)(codePtr + 6) = 0xE9;    //jmp  nearAddr
				*(UINT32 *)(codePtr + 7) = nearAddr - (UINT32)(codePtr + 6) - 5;
				localBranchOffset2 = (ULONG)(codePtr + 7);
				codePtr += 11;
				shadowPtr = OpAnalysisBuildJccCode(shadowPtr, recIndex, &localSbOffset, g_faultCodePage + 28);
				break;
			case UD_Ijnz:   //zf = 0, jne,jnz 0f 85
				*(UINT16 *)codePtr = 0x850F;        //jcc  farAddr
				*(UINT32 *)(codePtr + 2) = farAddr - (UINT32)codePtr - 6;
				localBranchOffset1 = (ULONG)(codePtr + 2);
				*(UINT8 *)(codePtr + 6) = 0xE9;    //jmp  nearAddr
				*(UINT32 *)(codePtr + 7) = nearAddr - (UINT32)(codePtr + 6) - 5;
				localBranchOffset2 = (ULONG)(codePtr + 7);
				codePtr += 11;
				shadowPtr = OpAnalysisBuildJccCode(shadowPtr, recIndex, &localSbOffset, g_faultCodePage + 32);
				break;
			case UD_Ijbe:  //cf = 1 or zf = 1, jna, 0f 86
				*(UINT16 *)codePtr = 0x860F;        //jcc  farAddr
				*(UINT32 *)(codePtr + 2) = farAddr - (UINT32)codePtr - 6;
				localBranchOffset1 = (ULONG)(codePtr + 2);
				*(UINT8 *)(codePtr + 6) = 0xE9;    //jmp  nearAddr
				*(UINT32 *)(codePtr + 7) = nearAddr - (UINT32)(codePtr + 6) - 5;
				localBranchOffset2 = (ULONG)(codePtr + 7);
				codePtr += 11;
				shadowPtr = OpAnalysisBuildJccCode(shadowPtr, recIndex, &localSbOffset, g_faultCodePage + 36);
				break;
			case UD_Ija:   //cf = 0 and zf = 0, jnbe, 0f 87
				*(UINT16 *)codePtr = 0x870F;        //jcc  farAddr
				*(UINT32 *)(codePtr + 2) = farAddr - (UINT32)codePtr - 6;
				localBranchOffset1 = (ULONG)(codePtr + 2);
				*(UINT8 *)(codePtr + 6) = 0xE9;     //jmp  nearAddr
				*(UINT32 *)(codePtr + 7) = nearAddr - (UINT32)(codePtr + 6) - 5;
				localBranchOffset2 = (ULONG)(codePtr + 7);
				codePtr += 11;
				shadowPtr = OpAnalysisBuildJccCode(shadowPtr, recIndex, &localSbOffset, g_faultCodePage + 40);
				break;
			case UD_Ijs: //sf = 1, 0f 88
				*(UINT16 *)codePtr = 0x880F;        //jcc  farAddr
				*(UINT32 *)(codePtr + 2) = farAddr - (UINT32)codePtr - 6;
				localBranchOffset1 = (ULONG)(codePtr + 2);
				*(UINT8 *)(codePtr + 6) = 0xE9;    //jmp  nearAddr
				*(UINT32 *)(codePtr + 7) = nearAddr - (UINT32)(codePtr + 6) - 5;
				localBranchOffset2 = (ULONG)(codePtr + 7);
				codePtr += 11;
				shadowPtr = OpAnalysisBuildJccCode(shadowPtr, recIndex, &localSbOffset, g_faultCodePage + 44);
				break;
			case UD_Ijns:   //sf = 0, 0f 89
				*(UINT16 *)codePtr = 0x890F;        //jcc  farAddr
				*(UINT32 *)(codePtr + 2) = farAddr - (UINT32)codePtr - 6;
				localBranchOffset1 = (ULONG)(codePtr + 2);
				*(UINT8 *)(codePtr + 6) = 0xE9;    //jmp  nearAddr
				*(UINT32 *)(codePtr + 7) = nearAddr - (UINT32)(codePtr + 6) - 5;
				localBranchOffset2 = (ULONG)(codePtr + 7);
				codePtr += 11;
				shadowPtr = OpAnalysisBuildJccCode(shadowPtr, recIndex, &localSbOffset, g_faultCodePage + 48);
				break;
			case UD_Ijp:    //pf = 1, jpe, 0f 8a
				*(UINT16 *)codePtr = 0x8A0F;        //jcc  farAddr
				*(UINT32 *)(codePtr + 2) = farAddr - (UINT32)codePtr - 6;
				localBranchOffset1 = (ULONG)(codePtr + 2);
				*(UINT8 *)(codePtr + 6) = 0xE9;    //jmp  nearAddr
				*(UINT32 *)(codePtr + 7) = nearAddr - (UINT32)(codePtr + 6) - 5;
				localBranchOffset2 = (ULONG)(codePtr + 7);
				codePtr += 11;
				shadowPtr = OpAnalysisBuildJccCode(shadowPtr, recIndex, &localSbOffset, g_faultCodePage + 52);
				break;
			case UD_Ijnp:   //pf = 0, jpo, 0f 8b
				*(UINT16 *)codePtr = 0x8B0F;        //jcc  farAddr
				*(UINT32 *)(codePtr + 2) = farAddr - (UINT32)codePtr - 6;
				localBranchOffset1 = (ULONG)(codePtr + 2);
				*(UINT8 *)(codePtr + 6) = 0xE9;    //jmp  nearAddr
				*(UINT32 *)(codePtr + 7) = nearAddr - (UINT32)(codePtr + 6) - 5;
				localBranchOffset2 = (ULONG)(codePtr + 7);
				codePtr += 11;
				shadowPtr = OpAnalysisBuildJccCode(shadowPtr, recIndex, &localSbOffset, g_faultCodePage + 56);
				break;
			case UD_Ijl:    //sf != 0F, jnge, 0f 8c
				*(UINT16 *)codePtr = 0x8C0F;        //jcc  farAddr
				*(UINT32 *)(codePtr + 2) = farAddr - (UINT32)codePtr - 6;
				localBranchOffset1 = (ULONG)(codePtr + 2);
				*(UINT8 *)(codePtr + 6) = 0xE9;    //jmp  nearAddr
				*(UINT32 *)(codePtr + 7) = nearAddr - (UINT32)(codePtr + 6) - 5;
				localBranchOffset2 = (ULONG)(codePtr + 7);
				codePtr += 11;
				shadowPtr = OpAnalysisBuildJccCode(shadowPtr, recIndex, &localSbOffset, g_faultCodePage + 60);
				break;
			case UD_Ijge:   //sf = of, jnl, 0f 8d
				*(UINT16 *)codePtr = 0x8D0F;        //jcc  farAddr
				*(UINT32 *)(codePtr + 2) = farAddr - (UINT32)codePtr - 6;
				localBranchOffset1 = (ULONG)(codePtr + 2);
				*(UINT8 *)(codePtr + 6) = 0xE9;    //jmp  nearAddr
				*(UINT32 *)(codePtr + 7) = nearAddr - (UINT32)(codePtr + 6) - 5;
				localBranchOffset2 = (ULONG)(codePtr + 7);
				codePtr += 11;
				shadowPtr = OpAnalysisBuildJccCode(shadowPtr, recIndex, &localSbOffset, g_faultCodePage + 64);
				break;
			case UD_Ijle:   //zf = 1 or sf != of, jng, 0f 8e
				*(UINT16 *)codePtr = 0x8E0F;        //jcc  farAddr
				*(UINT32 *)(codePtr + 2) = farAddr - (UINT32)codePtr - 6;
				localBranchOffset1 = (ULONG)(codePtr + 2);
				*(UINT8 *)(codePtr + 6) = 0xE9;    //jmp  nearAddr
				*(UINT32 *)(codePtr + 7) = nearAddr - (UINT32)(codePtr + 6) - 5;
				localBranchOffset2 = (ULONG)(codePtr + 7);
				codePtr += 11;
				shadowPtr = OpAnalysisBuildJccCode(shadowPtr, recIndex, &localSbOffset, g_faultCodePage + 68);
				break;
			case UD_Ijg:   //zf = 0 and sf = of, jnle 0f 8f
				*(UINT16 *)codePtr = 0x8F0F;        //jcc  farAddr
				*(UINT32 *)(codePtr + 2) = farAddr - (UINT32)codePtr - 6;
				localBranchOffset1 = (ULONG)(codePtr + 2);
				*(UINT8 *)(codePtr + 6) = 0xE9;    //jmp  nearAddr
				*(UINT32 *)(codePtr + 7) = nearAddr - (UINT32)(codePtr + 6) - 5;
				localBranchOffset2 = (ULONG)(codePtr + 7);
				codePtr += 11;
				shadowPtr = OpAnalysisBuildJccCode(shadowPtr, recIndex, &localSbOffset, g_faultCodePage + 72);
				break;
			default: //jcxz ?
				DbgPrint("[CHECK] Unknown type %d, start %x cur_ip %x\n", p_ud->mnemonic, processorData->dis_ip, curIp);
				__debugbreak();
			}
			curIp += disLen;
			break;
		}
		else if (p_ud->mnemonic == UD_Icall)
		{
			codePtr = OpBlockEnd(codePtr, &recIndex, &recReg, cacheBase, &cachePtr);
			*(UINT64 *)(codePtr) = 0x896400000070A364;    //mov fs:[70h], eax
			*(UINT64 *)(codePtr + 8) = 0x158964000000780D;//mov fs:[78h], ecx
			*(UINT32 *)(codePtr + 16) = 0x0000007C;       //mov fs:[7Ch], edx
			codePtr += 20;
			if (opr0->type == UD_OP_MEM) //call [esp+8]
			{
				if (p_ud->pfx_seg) //call -> mov ecx, cs:[xxxxx]
				{
					memcpy_fast_16(codePtr, (void *)curIp, disLen);
					*(UINT8 *)(codePtr + 1) = 0x8B;
					*(UINT8 *)(codePtr + 2) -= 8;
					codePtr += disLen;
				}
				else
				{
					memcpy_fast_16(codePtr, (void *)curIp, disLen);  //call -> mov ecx, [xxxxx]
					*(UINT8 *)(codePtr) = 0x8B;
					*(UINT8 *)(codePtr + 1) -= 8;
					codePtr += disLen;
				}
			}
			else
			{
				*(UINT8 *)(codePtr) = 0x8B;
				*(UINT8 *)(codePtr + 1) = (opr0->base - UD_R_EAX) + 0xC8; //mov ecx, REG0
				codePtr += 2;
			}
			*(UINT64 *)(codePtr) = 0x000000680D8964;   //mov  fs:[68h], ecx
			*(UINT32 *)(codePtr + 7) = 0xC0900F9F;     //lahf; seto al
			codePtr += 11;
			codePtr = OpRecordRet(codePtr, &recIndex, &recBlock, blockProfiler);
			memcpy(codePtr, g_emuCallJmpRetTemplReserved3, sizeof(g_emuCallJmpRetTemplReserved3));
			*(UINT32 *)(codePtr + 14) = (ULONG)g_code_table;
			codePtr += sizeof(g_emuCallJmpRetTemplReserved3);
			//push  next_addr
			*(UINT8 *)(codePtr) = 0x68;
			*(UINT32 *)(codePtr + 1) = curIp + disLen;
			*(UINT32 *)(codePtr + 5) = 0x6825FF64;      //jmp fs:[68h] 
			*(UINT32 *)(codePtr + 9) = 0x00000000;
			codePtr += 12; //5+7
			curIp += disLen;
			//shadow
			shadowPtr = OpAnalysisBuildIndirectJmp(shadowPtr, recIndex);
			break;
		}
		else if (p_ud->mnemonic == UD_Ijmp)  //jmp [ebx+8]; ff /4,
		{
			codePtr = OpBlockEnd(codePtr, &recIndex, &recReg, cacheBase, &cachePtr);
			*(UINT64 *)(codePtr) = 0x896400000070A364;    //mov fs:[70h], eax
			*(UINT64 *)(codePtr + 8) = 0x158964000000780D;//mov fs:[78h], ecx
			*(UINT32 *)(codePtr + 16) = 0x0000007C;       //mov fs:[7Ch], edx
			codePtr += 20;
			if (opr0->type == UD_OP_MEM) //jmp [esp+8]
			{
				memcpy_fast_16(codePtr, (void *)curIp, disLen); //jmp -> mov ecx, [xxxxx]
				*(UINT8 *)(codePtr) = 0x8B;
				*(UINT8 *)(codePtr + 1) -= 0x18;
				codePtr += disLen;
			}
			else
			{
				*(UINT8 *)(codePtr) = 0x8B;
				*(UINT8 *)(codePtr + 1) = (opr0->base - UD_R_EAX) + 0xC8; //mov ecx, REG0
				codePtr += 2;
			}
			*(UINT64 *)(codePtr) = 0x000000680D8964;   //mov  fs:[68h], ecx
			*(UINT32 *)(codePtr + 7) = 0xC0900F9F;     //lahf; seto al
			codePtr += 11;
			codePtr = OpRecordRet(codePtr, &recIndex, &recBlock, blockProfiler);
			memcpy(codePtr, g_emuCallJmpRetTemplReserved3, sizeof(g_emuCallJmpRetTemplReserved3));
			*(UINT32 *)(codePtr + 14) = (ULONG)g_code_table;
			codePtr += sizeof(g_emuCallJmpRetTemplReserved3);
			*(UINT32 *)(codePtr) = 0x6825FF64;
			*(UINT32 *)(codePtr + 4) = 0x00000000;
			codePtr += 7;
			curIp += disLen;
			//shadow
			shadowPtr = OpAnalysisBuildIndirectJmp(shadowPtr, recIndex);
			break;
		}
		else if (p_ud->mnemonic == UD_Iret) //ok
		{
			codePtr = OpBlockEnd(codePtr, &recIndex, &recReg, cacheBase, &cachePtr);
			*(UINT64 *)(codePtr) = 0x896400000070A364;    //mov fs:[70h], eax
			*(UINT64 *)(codePtr + 8) = 0x158964000000780D;//mov fs:[78h], ecx
			*(UINT32 *)(codePtr + 16) = 0x0000007C;       //mov fs:[7Ch], edx
			*(UINT32 *)(codePtr + 20) = 0x240C8B;         //mov ecx, [esp]
			*(UINT64 *)(codePtr + 23) = 0x000000680D8964; //mov  fs:[68h], ecx
			*(UINT32 *)(codePtr + 30) = 0xC0900F9F;       //lahf; seto al
			codePtr += 34;
			codePtr = OpRecordRet(codePtr, &recIndex, &recBlock, blockProfiler);
			memcpy(codePtr, g_emuCallJmpRetTemplReserved3, sizeof(g_emuCallJmpRetTemplReserved3));
			*(UINT32 *)(codePtr + 14) = (ULONG)g_code_table;
			codePtr += sizeof(g_emuCallJmpRetTemplReserved3);
			*(UINT64 *)(codePtr) = 0x0000000424A48D; //lea esp, [esp+4]
			if (opr0->type == UD_OP_IMM)             //ret imm16
			{
				*(UINT32 *)(codePtr + 3) = opr0->lval.uword + 4;
			}
			*(UINT32 *)(codePtr + 7) = 0x6825FF64;
			*(UINT32 *)(codePtr + 11) = 0x000000;
			codePtr += 14;
			curIp += disLen;
			shadowPtr = OpAnalysisBuildIndirectJmp(shadowPtr, recIndex);
			break;
		}
		else if (p_ud->mnemonic == UD_Isysenter)
		{
			codePtr = OpBlockEnd(codePtr, &recIndex, &recReg, cacheBase, &cachePtr);
			codePtr = OpRecordSysenter(codePtr, &recIndex, &recBlock, blockProfiler);
			memcpy_fast_16(codePtr, (void *)curIp, disLen);
			codePtr += disLen;
			blockProfiler->Syscall = LOG_SYSENTER_FLAG;
			curIp += disLen;

			*(UINT16 *)(shadowPtr) = 0x838B;    //mov  eax, [ebx+recIndex]
			*(UINT32 *)(shadowPtr + 2) = (recIndex - 1) * 4;
			*(UINT16 *)(shadowPtr + 6) = 0x008B;//mov  eax, dword ptr [eax]
			shadowPtr = OpAnalysisBuildIndirectJmp(shadowPtr + 8, recIndex);
			break;
		}
		//else //test
		//{
		//	memcpy_fast_16(cachePtr, (void *)curIp, disLen);
		//	cachePtr += disLen;
		//	curIp += disLen;
		//	continue;
		//}
		if (p_ud->pfx_seg == UD_R_FS)  
		{
			memcpy_fast_16(cachePtr, (void *)curIp, disLen);
			cachePtr += disLen;
			curIp += disLen;
			continue;
		}
		switch (p_ud->mnemonic)
		{
		case UD_Iadc:
		case UD_Iadd:
		case UD_Iand:
		case UD_Ior:
		case UD_Isbb:
		case UD_Isub:
		case UD_Ixor:
			if (opr1->type == UD_OP_IMM)
			{
				break;
			}
			if (opr1->type == UD_OP_MEM)    //add  ebx, [esp+8];
			{
				codePtr = OpRecordBlockAddr(codePtr, &p_ud->operand[1], &recIndex, &recReg, &recBlock,
					blockProfiler, cacheBase, &cachePtr);
				shadowPtr = OpLoadRecordAddrGeneral(shadowPtr, p_ud, 1, recIndex);
				if (opr0->size == 32)
				{
					*(UINT32 *)(shadowPtr) = 0x4209018B;               //mov eax, [ecx]
					*(UINT8 *)(shadowPtr + 4) = (44 - opr0->base) * 4; //or [edx+REG], eax
					shadowPtr += 5;
				}
				else if (opr0->size == 16)
				{
					*(UINT32 *)(shadowPtr) = 0x66018B66;    //mov ax, [ecx]
					*(UINT16 *)(shadowPtr + 4) = 0x4209;    //or  word ptr [edx+REG], ax
					*(UINT8 *)(shadowPtr + 6) = (28 - opr0->base) * 4;
					shadowPtr += 7;
				}
				else
				{
					bh0 = opr0->base / UD_R_AH;
					bi0 = opr0->base - (UD_R_AH - 1)*bh0;
					*(UINT32 *)(shadowPtr) = 0x4208018A;             //mov al, [ecx]
					*(UINT8 *)(shadowPtr + 4) = (8 - bi0) * 4 + bh0; //or  byte ptr [edx+REG], al
					shadowPtr += 5;
				}
				*(UINT8 *)(shadowPtr) = 0xC3; //ret
			}
			else if (opr0->type == UD_OP_MEM) //adc  [esp+8], ebx; ok
			{
				codePtr = OpRecordBlockAddr(codePtr, &p_ud->operand[0], &recIndex, &recReg, &recBlock,
					blockProfiler, cacheBase, &cachePtr);
				shadowPtr = OpLoadRecordAddrGeneral(shadowPtr, p_ud, 0, recIndex);
				if (opr1->size == 32)
				{
					*(UINT16 *)shadowPtr = 0x428B;       //mov eax, [edx+REG] 
					*(UINT8 *)(shadowPtr + 2) = (44 - opr1->base) * 4;
					*(UINT16 *)(shadowPtr + 3) = 0x0109; //or [ecx], eax
					shadowPtr += 5;
				}
				else if (opr1->size == 16)
				{
					*(UINT32 *)shadowPtr = 0x428B66;        //mov ax,word ptr [edx+REG]
					*(UINT8 *)(shadowPtr + 3) = (28 - opr1->base) * 4;
					*(UINT32 *)(shadowPtr + 4) = 0x010966;  //or word ptr [ecx], ax
					shadowPtr += 7;
				}
				else
				{
					bh1 = opr1->base / UD_R_AH;
					bi1 = opr1->base - (UD_R_AH - 1)*bh1;
					*(UINT16 *)shadowPtr = 0x428A;      //mov al, [edx+REG] 
					*(UINT8 *)(shadowPtr + 2) = (8 - bi1) * 4 + bh1;
					*(UINT16 *)(shadowPtr + 3) = 0x0108; //or [ecx], al
					shadowPtr += 5;
				}
				*(UINT8 *)(shadowPtr) = 0xC3; //ret
			}
			else //add ebx, eax ; ok
			{
				if (opr0->base == opr1->base) //sub/sbb/xor eax, eax
				{
					if ((p_ud->mnemonic == UD_Isbb) || (p_ud->mnemonic == UD_Isub) ||
						(p_ud->mnemonic == UD_Ixor))
					{
						if (opr0->size == 32)
						{
							*(UINT16 *)shadowPtr = 0x42C7; //mov [edx + REG], 0
							*(UINT8 *)(shadowPtr + 2) = (44 - opr0->base) * 4;
							*(UINT32 *)(shadowPtr + 3) = 0;
							shadowPtr += 7;
						}
						else if (opr0->size == 16)
						{
							*(UINT32 *)shadowPtr = 0x42C766;//mov word ptr [edx + REG], 0
							*(UINT8 *)(shadowPtr + 3) = (28 - opr0->base) * 4;
							*(UINT16 *)(shadowPtr + 4) = 0;
							shadowPtr += 6;
						}
						else
						{
							bh0 = opr0->base / UD_R_AH;
							bi0 = opr0->base - (UD_R_AH - 1)*bh0;
							*(UINT32 *)shadowPtr = 0x000042C6; //mov byte ptr [edx + REG], 0
							*(UINT8 *)(shadowPtr + 2) = (8 - bi0) * 4 + bh0;
							shadowPtr += 4;
						}
						*(UINT8 *)(shadowPtr) = 0xC3; //ret
					}
				}
				else
				{
					if (opr0->size == 32)
					{
						*(UINT16 *)shadowPtr = 0x428B;       //mov eax, [edx + REG1]
						*(UINT8 *)(shadowPtr + 2) = (44 - opr1->base) * 4;
						*(UINT16 *)(shadowPtr + 3) = 0x4209; //or [edx + REG0], eax
						*(UINT8 *)(shadowPtr + 5) = (44 - opr0->base) * 4;
						shadowPtr += 6;
					}
					else if (opr0->size == 16)
					{
						*(UINT32 *)shadowPtr = 0x428B66;       //mov ax, [edx + REG1]
						*(UINT8 *)(shadowPtr + 3) = (28 - opr1->base) * 4;
						*(UINT32 *)(shadowPtr + 4) = 0x420966; //or [edx + REG0], ax
						*(UINT8 *)(shadowPtr + 7) = (28 - opr0->base) * 4;
						shadowPtr += 8;
					}
					else
					{
						bh0 = opr0->base / UD_R_AH;
						bi0 = opr0->base - (UD_R_AH - 1)*bh0;
						bh1 = opr1->base / UD_R_AH;
						bi1 = opr1->base - (UD_R_AH - 1)*bh1;
						*(UINT16 *)shadowPtr = 0x428A;       //mov al, byte ptr [edx + REG1]
						*(UINT8 *)(shadowPtr + 2) = (8 - bi1) * 4 + bh1;
						*(UINT16 *)(shadowPtr + 3) = 0x4208; //or byte ptr  [edx + REG0], al
						*(UINT8 *)(shadowPtr + 5) = (8 - bi0) * 4 + bh0;
						shadowPtr += 6;
					}
					*(UINT8 *)(shadowPtr) = 0xC3;
				}
			}
			break;
		case UD_Imov:
		case UD_Ibsf:
		case UD_Ibsr:
			if (opr1->type == UD_OP_IMM) //ok
			{
				if (opr0->type == UD_OP_MEM) //mov  [eax], 8
				{
					codePtr = OpRecordBlockAddr(codePtr, &p_ud->operand[0], &recIndex, &recReg, &recBlock,
						blockProfiler, cacheBase, &cachePtr);
					shadowPtr = OpLoadRecordAddrGeneral(shadowPtr, p_ud, 0, recIndex);
					if (opr0->size == 32)
					{
						*(UINT32 *)(shadowPtr) = 0x000001C7;  //mov [ecx],  0
						*(UINT16 *)(shadowPtr + 4) = 0x0000;
						shadowPtr += 6;
					}
					else if (opr0->size == 16)
					{
						*(UINT32 *)(shadowPtr) = 0x0001C766;  //mov word ptr [ecx], 0
						*(UINT8 *)(shadowPtr + 4) = 0x00;
						shadowPtr += 5;
					}
					else
					{
						*(UINT32 *)(shadowPtr) = 0x0001C6;   //mov byte ptr [ecx], 0
						shadowPtr += 3;
					}
					*(UINT8 *)(shadowPtr) = 0xC3;
				}
				else //mov eax, 8
				{
					if (opr0->size == 32)
					{
						*(UINT16 *)shadowPtr = 0x42C7;          //mov [edx + REG0], 0
						*(UINT8 *)(shadowPtr + 2) = (44 - opr0->base) * 4;
						*(UINT32 *)(shadowPtr + 3) = 0;
						shadowPtr += 7;
					}
					else if (opr0->size == 16)
					{
						*(UINT32 *)shadowPtr = 0x0042C766;     //mov word ptr [edx + REG0], 0
						*(UINT8 *)(shadowPtr + 3) = (28 - opr0->base) * 4;
						*(UINT16 *)(shadowPtr + 4) = 0x0000;
						shadowPtr += 6;
					}
					else
					{
						bh0 = opr0->base / UD_R_AH;
						bi0 = opr0->base - (UD_R_AH - 1)*bh0;
						*(UINT16 *)shadowPtr = 0x42C6;         //mov byte ptr [edx + REG0], 0
						*(UINT8 *)(shadowPtr + 2) = (8 - bi0) * 4 + bh0;
						*(UINT8 *)(shadowPtr + 3) = 0x00;
						shadowPtr += 4;
					}
					*(UINT8 *)(shadowPtr) = 0xC3; //ret
				}
			}
			else if (opr1->type == UD_OP_MEM) //mov eax, [ebx+ecx*8]; ok
			{
				codePtr = OpRecordBlockAddr(codePtr, &p_ud->operand[1], &recIndex, &recReg, &recBlock,
					blockProfiler, cacheBase, &cachePtr);
				shadowPtr = OpLoadRecordAddrGeneral(shadowPtr, p_ud, 1, recIndex);
				if (opr0->size == 32)
				{
					*(UINT32 *)(shadowPtr) = 0x4289018B;               //mov eax, [ecx]
					*(UINT8 *)(shadowPtr + 4) = (44 - opr0->base) * 4; //mov [edx+REG], eax
					shadowPtr += 5;
				}
				else if (opr0->size == 16)          //mov  ax, word ptr [ebx+eax*8]
				{
					*(UINT32 *)(shadowPtr) = 0x66018B66;    //mov  ax, [ecx]
					*(UINT16 *)(shadowPtr + 4) = 0x4289;    //mov  word ptr [edx+REG], ax
					*(UINT8 *)(shadowPtr + 6) = (28 - opr0->base) * 4;
					shadowPtr += 7;
					//for notepad
					//if ((opr1->base != UD_NONE) && (opr1->index != UD_NONE))
					//{
					//	*(UINT32 *)(shadowPtr) = 0x66018B66;    //mov  ax, [ecx]
					//	*(UINT16 *)(shadowPtr + 4) = 0x7A8B;    //mov  di, word ptr [edx+INDEX]  
					//	*(UINT8 *)(shadowPtr + 6) = (44 - opr1->index) * 4;
					//	*(UINT32 *)(shadowPtr + 7) = 0x66C70B66;//or   ax, di
					//	*(UINT16 *)(shadowPtr + 11) = 0x4289;   //mov  word ptr [edx+REG], ax
					//	*(UINT8 *)(shadowPtr + 13) = (28 - opr0->base) * 4;
					//	shadowPtr += 14;
					//}
					//else
					//{
					//	*(UINT32 *)(shadowPtr) = 0x66018B66;    //mov  ax, [ecx]
					//	*(UINT16 *)(shadowPtr + 4) = 0x4289;    //mov  word ptr [edx+REG], ax
					//	*(UINT8 *)(shadowPtr + 6) = (28 - opr0->base) * 4;
					//	shadowPtr += 7;
					//}
				}
				else
				{
					bh0 = opr0->base / UD_R_AH;
					bi0 = opr0->base - (UD_R_AH - 1)*bh0;
					*(UINT32 *)(shadowPtr) = 0x4288018A;    //mov al, [ecx]
					*(UINT8 *)(shadowPtr + 4) = (8 - bi0) * 4 + bh0; //mov byte ptr [edx+REG], al
					shadowPtr += 5;
				}
				*(UINT8 *)(shadowPtr) = 0xC3; //ret
			}
			else if (opr0->type == UD_OP_MEM) //mov [ebx+ecx*8]£¬ eax; ok
			{
				codePtr = OpRecordBlockAddr(codePtr, &p_ud->operand[0], &recIndex, &recReg, &recBlock,
					blockProfiler, cacheBase, &cachePtr);
				shadowPtr = OpLoadRecordAddrGeneral(shadowPtr, p_ud, 0, recIndex);
				if (opr1->size == 32)
				{
					*(UINT16 *)shadowPtr = 0x428B;      //mov eax, [edx+REG] 
					*(UINT8 *)(shadowPtr + 2) = (44 - opr1->base) * 4;
					*(UINT16 *)(shadowPtr + 3) = 0x0189; //mov [ecx], eax
					shadowPtr += 5;
				}
				else if (opr1->size == 16)
				{
					*(UINT32 *)shadowPtr = 0x428B66;        //mov ax,word ptr [edx+REG]
					*(UINT8 *)(shadowPtr + 3) = (28 - opr1->base) * 4;
					*(UINT32 *)(shadowPtr + 4) = 0x018966;  //mov word ptr [ecx], ax
					shadowPtr += 7;
				}
				else
				{
					bh1 = opr1->base / UD_R_AH;
					bi1 = opr1->base - (UD_R_AH - 1)*bh1;
					*(UINT16 *)shadowPtr = 0x428A;       //mov al, [edx+REG] 
					*(UINT8 *)(shadowPtr + 2) = (8 - bi1) * 4 + bh1;
					*(UINT16 *)(shadowPtr + 3) = 0x0188; //mov [ecx], al
					shadowPtr += 5;
				}
				*(UINT8 *)(shadowPtr) = 0xC3; //ret
			}
			else //mov eax, ebx; ok
			{
				if (opr0->base == opr1->base) //mov edi, edi
				{
					break;
				}
				if (opr0->size == 32)
				{
					*(UINT16 *)shadowPtr = 0x428B;       //mov eax, [edx + REG1]
					*(UINT8 *)(shadowPtr + 2) = (44 - opr1->base) * 4;
					*(UINT16 *)(shadowPtr + 3) = 0x4289; //mov [edx + REG0], eax
					*(UINT8 *)(shadowPtr + 5) = (44 - opr0->base) * 4;
					shadowPtr += 6;
				}
				else if (opr0->size == 16)
				{
					*(UINT32 *)shadowPtr = 0x428B66;      //mov ax, [edx + REG1]
					*(UINT8 *)(shadowPtr + 3) = (28 - opr1->base) * 4;
					*(UINT32 *)(shadowPtr + 4) = 0x428966; //mov [edx + REG0], ax
					*(UINT8 *)(shadowPtr + 7) = (28 - opr0->base) * 4;
					shadowPtr += 8;
				}
				else
				{
					bh0 = opr0->base / UD_R_AH;
					bi0 = opr0->base - (UD_R_AH - 1)*bh0;
					bh1 = opr1->base / UD_R_AH;
					bi1 = opr1->base - (UD_R_AH - 1)*bh1;
					*(UINT16 *)shadowPtr = 0x428A;       //mov al, byte ptr [edx + REG1]
					*(UINT8 *)(shadowPtr + 2) = (8 - bi1) * 4 + bh1;
					*(UINT16 *)(shadowPtr + 3) = 0x4288; //mov byte ptr  [edx + REG0], al
					*(UINT8 *)(shadowPtr + 5) = (8 - bi0) * 4 + bh0;
					shadowPtr += 6;
				}
				*(UINT8 *)(shadowPtr) = 0xC3; //ret
			}
			break;
		/* Similarly add the processing code for other instructions */
		/* ... */
		default:
			break;
		}
		memcpy_fast_16(cachePtr, (void *)curIp, disLen);
		cachePtr += disLen;
		curIp += disLen;
	}

	*(UINT32 *)(countPtr) = recIndex * 4;

	LONG existedCode = InterlockedCompareExchange((LONG *)&blockProfiler->CodeBytesPtr, (LONG)codeBase, 0);
	if (existedCode == 0) 
	{
		ULONG  mapAddr = (ULONG)g_code_table[faultIp >> 12] + (faultIp & 0xFFF) * 4;
		InterlockedExchange((LONG *)mapAddr, (LONG)codeBase);
		if ((LONG *)mapAddr == 0)
		{
			DbgPrint("Parse check, mapAddr %x, faultIp %x, codeBase %x\n",
				mapAddr, faultIp, codeBase);
			HYPERPLATFORM_COMMON_DBG_BREAK();
		}
		blockProfiler->BranchOffset1 = localBranchOffset1;
		blockProfiler->BranchOffset2 = localBranchOffset2;
		blockProfiler->AnalysisCodePtr = analysisBase;
		blockProfiler->SbOffset1 = localSbOffset.SbOffset1;
		blockProfiler->SbOffset2 = localSbOffset.SbOffset2;
		blockProfiler->CompOffset2 = localSbOffset.CompOffset2;

		processorData->buf_ptr = (ULONG)codePtr;
		processorData->asbuf_ptr = (ULONG)shadowPtr;
		blockProfiler->BlockHash = DJBHash((char *)faultIp, blockProfiler->BlockSize);	

		if (blockProfiler->BranchOffset1)
		{
			BLOCK_PROFILER *farProfiler = (BLOCK_PROFILER *)GetAllocBlockProfiler(processorData, farAddr);
			if (farProfiler->CodeBytesPtr)
			{
				InterlockedExchange((LONG *)blockProfiler->BranchOffset1,
					farProfiler->CodeBytesPtr - blockProfiler->BranchOffset1 - 4);
				InterlockedExchange((LONG *)blockProfiler->SbOffset1,
					(ULONG)farProfiler->AnalysisCodePtr - blockProfiler->SbOffset1 - 4);

			}
			else
			{
				FROM_NODE *pNode = (FROM_NODE *)processorData->hdbuf_ptr;
				processorData->hdbuf_ptr += sizeof(FROM_NODE);
				pNode->Profiler = blockProfiler;
				ExInterlockedPushEntryList(&farProfiler->FromListHead, &pNode->ListEntry, &farProfiler->Lock);
			}
		}
		if (blockProfiler->BranchOffset2)
		{
			BLOCK_PROFILER *nearProfiler = (BLOCK_PROFILER *)GetAllocBlockProfiler(processorData, nearAddr);
			if (nearProfiler->CodeBytesPtr)
			{
				InterlockedExchange((LONG *)blockProfiler->BranchOffset2,
					nearProfiler->CodeBytesPtr - blockProfiler->BranchOffset2 - 4);
				InterlockedExchange((LONG *)blockProfiler->SbOffset2,
					(ULONG)nearProfiler->AnalysisCodePtr - blockProfiler->SbOffset2 - 4);
				InterlockedExchange((LONG *)blockProfiler->CompOffset2, (ULONG)nearProfiler);
			}
			else
			{
				FROM_NODE *pNode = (FROM_NODE *)processorData->hdbuf_ptr;
				processorData->hdbuf_ptr += sizeof(FROM_NODE);
				pNode->Profiler = blockProfiler;
				ExInterlockedPushEntryList(&nearProfiler->FromListHead, &pNode->ListEntry, &nearProfiler->Lock);
			}
		}
		processorData->counter_2 += insCount;
	}
}

void __stdcall CodePageRewritingBlockLink(ProcessorData *processorData,
	thread_ctx_t *pThreadData, PKEPT_FAULT_FRAME pTrapFrame)
{
	ULONG  faultIp = pTrapFrame->Eip;

	BLOCK_PROFILER *pBlockProfiler = (BLOCK_PROFILER *)GetAllocBlockProfiler(processorData, faultIp);

	if (pBlockProfiler->CodeBytesPtr)
	{
		if (pBlockProfiler->Flag == 1)  //Rollback
		{
			ULONG codeBase = pBlockProfiler->CodeBytesPtr;
			ULONG blockHash = DJBHash((char *)faultIp, pBlockProfiler->BlockSize);
			if (blockHash != pBlockProfiler->BlockHash)
			{		
				//Patch£¬jmp NewCodeBytes
				//*(UINT8 *)(codeBase) = 0xE9;
				//*(UINT32 *)(codeBase + 1) = newCodeBase - (ULONG)(codeBase)-5;
			}
			else
			{
				//restore nop word ptr [eax+eax+]
				//InterlockedExchange16((SHORT *)&pBlockProfiler->Flag, 0);
				//*(UINT32 *)(codeBase) = 0x841F0F66;
				//*(UINT8 *)(codeBase + 4) = 0x00;
			}
		}
	}
	else
	{
		ParseBuildBlockLinkRecord(processorData, pBlockProfiler, faultIp);
		processorData->counter_1++;
	}

	while (1)
	{
		PSINGLE_LIST_ENTRY pEntry = ExInterlockedPopEntryList(&pBlockProfiler->FromListHead, &pBlockProfiler->Lock);
		if (!pEntry)
		{
			break;
		}
		BLOCK_PROFILER *fromProfiler = CONTAINING_RECORD(pEntry, FROM_NODE, ListEntry)->Profiler;
		if (fromProfiler->BranchOffset1)
		{
			ULONG orgRelDisp = pBlockProfiler->FaultIp - fromProfiler->BranchOffset1 - 4;
			ULONG oldValue = InterlockedCompareExchange((LONG *)fromProfiler->BranchOffset1,
				pBlockProfiler->CodeBytesPtr - fromProfiler->BranchOffset1 - 4, orgRelDisp);
			if (oldValue == orgRelDisp)
			{
				InterlockedExchange((LONG *)fromProfiler->SbOffset1,
					(ULONG)pBlockProfiler->AnalysisCodePtr - fromProfiler->SbOffset1 - 4);
			}
		}
		if (fromProfiler->BranchOffset2)
		{
			ULONG orgRelDisp = pBlockProfiler->FaultIp - fromProfiler->BranchOffset2 - 4;
			ULONG oldValue = InterlockedCompareExchange((LONG *)fromProfiler->BranchOffset2,
				pBlockProfiler->CodeBytesPtr - fromProfiler->BranchOffset2 - 4, orgRelDisp);
			if (oldValue == orgRelDisp)
			{
				InterlockedExchange((LONG *)fromProfiler->SbOffset2,
					(ULONG)pBlockProfiler->AnalysisCodePtr - fromProfiler->SbOffset2 - 4);
				InterlockedExchange((LONG *)fromProfiler->CompOffset2, (ULONG)pBlockProfiler);
			}
		}
	}

	if (!pThreadData->start)
	{
		pThreadData->start = 1;
		pThreadData->analysis_base = pBlockProfiler->AnalysisCodePtr;
		DbgPrint(" [init] tid %d, BlockProfiler %x, FaultIp %x, CodeBytesPtr %x, AnalysisCodePtr %x.\n",
			pThreadData->tid, pBlockProfiler, pBlockProfiler->FaultIp,
			pBlockProfiler->CodeBytesPtr, pBlockProfiler->AnalysisCodePtr);
	}

	pTrapFrame->Eip = pBlockProfiler->CodeBytesPtr;
}

PVOID __stdcall AnalysisCheckBuffer(thread_ctx_t *ThreadCtx, ULONG BufferProbe, ULONG BufferPtr, ULONG *BufferLimit)
{
	KeWaitForSingleObject(&ThreadCtx->full_list.semaphore, Executive, KernelMode, FALSE, NULL);
	LIST_ELEMENT *nextOutBuffer = (LIST_ELEMENT *)ExInterlockedRemoveHeadList(&ThreadCtx->full_list.listhead,
		&ThreadCtx->full_list.spinlock);

	if (ThreadCtx->out_buffer->real == NULL)
	{
		DbgPrint("[AnalysisCheckBuffer] CHECK. real null, out_buffer %x, BufferPtr %x, nextOutBuffer %x\n", 
			ThreadCtx->out_buffer, BufferPtr, nextOutBuffer);
		HYPERPLATFORM_COMMON_DBG_BREAK();
	}

	ULONG nextBase = (ULONG)nextOutBuffer->base;
	ULONG copyLen = (ULONG)ThreadCtx->out_buffer->real - BufferPtr;
	if (copyLen)
	{
		if (copyLen > PAGE_SIZE)
		{
			DbgPrint("[AnalysisCheckBuffer] CHECK. overflow, out_buffer %x, base %x, curr %x, real %x, BufferPtr %x, pending %x, running %x\n", 
				ThreadCtx->out_buffer, ThreadCtx->out_buffer->base, ThreadCtx->out_buffer->curr, 
				ThreadCtx->out_buffer->real, BufferPtr, ThreadCtx->in_buffer_pending, ThreadCtx->running);
			HYPERPLATFORM_COMMON_DBG_BREAK();
		}
		nextBase -= copyLen;
		memcpy((PVOID)nextBase, (PVOID)BufferPtr, copyLen);
	}
	(*BufferLimit) = (ULONG)nextOutBuffer->curr;

	ExInterlockedInsertTailList(&ThreadCtx->free_list.listhead, &ThreadCtx->out_buffer->entry,
		&ThreadCtx->free_list.spinlock);
	KeReleaseSemaphore(&ThreadCtx->free_list.semaphore, IO_NO_INCREMENT, 1, FALSE);

	ThreadCtx->out_buffer = nextOutBuffer;

	return (PVOID)nextBase;
}

}

