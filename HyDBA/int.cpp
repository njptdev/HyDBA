#include "int.h"
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

extern "C" {

extern PVOID   g_target_eprocess;
extern ProcessorData *processor_list[];
extern UCHAR   instr_template[];
extern UCHAR   exec_template_head[];
extern UCHAR   exec_template_tail[];
extern ULONG   output_flag;
extern ULONG   output_flag2;
extern ULONG   g_module_addr[];

UCHAR cmovOpCode[] = { 0x47,0x43,0x42,0x46,0x4f,0x4d,0x4c,0x4e,
					  0x41,0x4b,0x49,0x45,0x40,0x4a,0x48,0x44 };
USHORT setccOpCode[] = { 0x0197,0x0193,0x0192,0x0196,0x019F,0x019d,0x019C,0x019E,
                      0x0191,0x019B,0x0199,0x0195,0x0190,0x019A,0x0198,0x0194 };

extern ULONG g_codeDispatchAddr;
extern ULONG g_user32_base;
extern ULONG g_ntdll_base;
extern ULONG g_kernel_base;
extern ULONG g_exec_count2;

extern PVOID   *g_code_table;
extern PVOID     *g_entry_table;

extern SharedProcessorData *g_shared_data;
extern PfnZwProtectVirtualMemory pZwProtectVirtualMemory;
extern PfnZwWriteVirtualMemory   pZwWriteVirtualMemory;
extern PfnNtQueryVirtualMemory   pNtQueryVirtualMemory;

extern PfnKeInsertQueueApc KeInsertQueueApc;

PUCHAR  kBitmap = NULL;

extern ULONG   g_target_pid;
extern ULONG   g_divisor;
extern ULONG   g_initCodePage;
extern ULONG   g_checkCodePage;

extern KSPIN_LOCK g_ipi_spinlock;
extern ULONG     *g_page_state;

extern ULONG    g_local_apic;
extern ULONG    g_cpu_apid_id[];
extern ULONG    g_debug_flag;

extern ULONG   g_athread_count;
extern KEVENT  g_athread_event;

extern PVOID   g_pt_map[2][512];

ULONG  g_ipi_flag = 0;
ULONG  g_fault_count = 0;

VOID   UpdateEptEntry(EptData *ept_data, ULONG64 pa, ULONG ept_value);
PVOID  AllocateFromUserSpaceCache(SIZE_T size);
PVOID  AllocateFromUserSpaceBufferEntries(ULONG va);
void __stdcall CodePageRewritingBlockLink(ProcessorData *processorData,
	thread_ctx_t *pThreadData, PKEPT_FAULT_FRAME pTrapFrame);


#define OPRAND_NONE    11

#define SKIP_INS       0
#define INLINE_OP_INS     1
#define SHADOW_OP_INS     2


UCHAR g_emuCallJmpRetTemplLatest[] = {
	0x8B,0xD1,                           //mov         edx,ecx
	0xC1,0xE9,0x0C,                      //shr         ecx,0Ch  
	0x81,0xE2,0xFF,0x0F,0x00,0x00,       //and         edx,0FFFh  
	0x8B,0x0C,0x8D,0x00,0x00,0x00,0x00,  //mov         ecx,dword ptr [ecx*4 + g_codeTable]  
	0x8B,0x0C,0x91,                      //mov         ecx,dword ptr [ecx + edx*4] 
	0x64,0x89,0x0D,0x68,0x00,0x00,0x00,  //mov         dword ptr fs:[68h],ecx
	0x04,0x7F,                           //add         al,7Fh
	0x9E,                                //sahf
	0x64,0x8B,0x15,0x7C,0x00,0x00,0x00,  //mov         edx,dword ptr fs:[7Ch] 
	0x64,0x8B,0x0D,0x78,0x00,0x00,0x00,  //mov         ecx,dword ptr fs:[78h]
	0x64,0xA1,0x70,0x00,0x00,0x00,       //mov         eax,dword ptr fs:[70h]
};

unsigned int DJBHash(char *str, unsigned int len)
{
	unsigned int hash = 5381;
	unsigned int i = 0;
	while (i < len) {
		hash = ((hash << 5) + hash) + (*str++); /* times 33 */
		i++;
	}
	hash &= ~(1 << 31); /* strip the highest bit */
	return hash;
}

ULONG_PTR IpiEptMonitorSwapContext(ULONG_PTR Argument)
{
	thread_ctx_t * p_thread_ctx = (thread_ctx_t *)Argument;
	ULONG          value = 0;

	ULONG pcr = AsmGetPcr();
	ULONG eptp = *(ULONG *)(pcr + KPCR_EPTP_OFFSET);
	if (eptp == EPTP_MONITOR1)
	{
		AsmVmFunc(0, EPTP_MONITOR1);
		for (ULONG i = 0; i < 2; i++)
		{
			ULONG page = (ULONG)p_thread_ctx->monitor_page_base + i * PAGE_SIZE;
			if ((PVOID)page == p_thread_ctx->in_buffer->limit)
			{
				break;
			}
			__invlpg((PVOID)page);
		}
	}
	
	return 0;
}

ULONG_PTR IpiEptMonitorPendingFault(ULONG_PTR Argument)
{
	thread_ctx_t * p_thread_ctx = (thread_ctx_t *)Argument;
	ULONG          value = 0;

	ULONG pcr = AsmGetPcr();
	ULONG eptp = *(ULONG *)(pcr + KPCR_EPTP_OFFSET);
	if (eptp == EPTP_MONITOR1)
	{
		AsmVmFunc(0, EPTP_MONITOR1);
		for (ULONG i = 0; i < 2; i++)
		{
			ULONG page = (ULONG)p_thread_ctx->monitor_page_base + i * PAGE_SIZE;
			if ((PVOID)page == p_thread_ctx->in_buffer->limit)
			{
				break;
			}
			__invlpg((PVOID)page);
		}
	}
	/*else
	{
		DbgPrint("[IpiEptMonitorPendingFault] cpu %d, tid %d, eptp %d\n",
			KeGetCurrentProcessorNumber(), PsGetCurrentThreadId(), eptp);
	}*/

	return 0;
}

ULONG_PTR IpiEptMonitorResetGuardPages(ULONG_PTR Argument)
{
	ULONG pcr = AsmGetPcr();
	if (*(ULONG *)(pcr + KPCR_EPTP_OFFSET) == EPTP_MONITOR1)
	{
		AsmVmFunc(0, EPTP_MONITOR1);
	}

	return 0;
}

//#pragma optimize( "", off )

void __stdcall IntKiServiceCheckWait(thread_ctx_t *p_thread_ctx, PKTRAP_FRAME pTrapFrame)
{
	FAULT_PROFILER *pLastProfiler = (FAULT_PROFILER *)*(ULONG *)(p_thread_ctx->teb + TEB_PROFILER_OFFSET); 
	
	//DbgPrint("IntKiServiceCheckWait. pLastProfiler %x, return eip %08x\n",
	//	pLastProfiler, pTrapFrame->Eip);

	if (pLastProfiler && (pLastProfiler->Syscall == LOG_SYSENTER_FLAG))
	{
		//DbgPrint("%d. ServiceCheck push %08x, addr %x, pLastProfiler %x.\n",
		//	p_thread_ctx->tid, pTrapFrame->Eip, logBufPtr - 4, pLastProfiler);

		ULONG  block_ip = pTrapFrame->Eip;
		PVOID  codePage = g_code_table[block_ip >> 12];
		if (((ULONG)codePage & 0xFFF00000) != ANALYSIS_CODE_FAULT_BASE)
		{
			ULONG codeBytesBase = *(ULONG *)((ULONG)codePage + (block_ip & 0xFFF) * 4);
			if (codeBytesBase != block_ip)
			{
				pTrapFrame->Eip = codeBytesBase;
			}
		}
	}
}

void __stdcall IntKiCallUserExitCheckWait(thread_ctx_t *p_thread_ctx, ULONG block_ip)
{
	FAULT_PROFILER *pLastProfiler = (FAULT_PROFILER *)*(ULONG *)(p_thread_ctx->teb + TEB_PROFILER_OFFSET);

	//DbgPrint("IntKiServiceCheckWait. pLastProfiler %x, return eip %08x\n",
	//	pLastProfiler, pTrapFrame->Eip);

	if (pLastProfiler && (pLastProfiler->Syscall == LOG_SYSENTER_FLAG))
	{
		//DbgPrint("%d. ServiceCheck push %08x, addr %x, pLastProfiler %x.\n",
		//	p_thread_ctx->tid, pTrapFrame->Eip, logBufPtr - 4, pLastProfiler);
		//edx, sysexit
	}
}

VOID __stdcall IntKiFastCallEntryHandler(PKTRAP_FRAME3 pTrapFrame)
{
	if (g_target_pid != (ULONG)PsGetCurrentProcessId())
	{
		return;
	}
	thread_ctx_t *p_thread_ctx = GET_THREAD_CTX();
	if (p_thread_ctx && p_thread_ctx->start)
	{
		p_thread_ctx->va_value = 1;
		//DbgPrint("-{sysenter} thread %d, eax %x, edx %x\n", 
		//	p_thread_ctx->tid, pTrapFrame->Eax, pTrapFrame->Edx);
	}
}


VOID __stdcall IntKiServiceExitHandler(PKTRAP_FRAME pTrapFrame)
{
	if (g_target_pid != (ULONG)PsGetCurrentProcessId())
	{
		return;
	}
	thread_ctx_t *p_thread_ctx = GET_THREAD_CTX();
	if (p_thread_ctx && p_thread_ctx->start && (pTrapFrame->SegCs != 8))
	{
		p_thread_ctx->va_value = 0;
		//sysenter
		IntKiServiceCheckWait(p_thread_ctx, pTrapFrame);
		if (pTrapFrame->Eip == (g_ntdll_base + 0x845d0)) //ntdll!KiUserApcDispatcher
		{
			DbgPrint("-{sysexit} APC. thread %d, kframe esp %x, eip %08x\n", p_thread_ctx->tid,
				pTrapFrame->HardwareEsp, pTrapFrame->Eip);
		}
		else if (pTrapFrame->Eip == (g_ntdll_base + 0x84640)) //ntdll!KiUserCallbackDispatcher
		{
			DbgPrint("-{sysexit} CALLBACK. thread %d, kframe esp %x, eip %08x\n", p_thread_ctx->tid,
				pTrapFrame->HardwareEsp, pTrapFrame->Eip);
		}
		else  //common sysexit
		{
			//DbgPrint("-{sysexit} thread %d, kframe esp %x, eip %08x\n", p_thread_ctx->tid,
			//	pTrapFrame->HardwareEsp, pTrapFrame->Eip);
		}
	}
}

VOID __stdcall IntKiCallUserModeExitHandler(PKTRAP_FRAME pTrapFrame)
{
	if (g_target_pid != (ULONG)PsGetCurrentProcessId())
	{
		return;
	}
	thread_ctx_t *p_thread_ctx = GET_THREAD_CTX();
	if (p_thread_ctx && p_thread_ctx->start)
	{
		//DbgPrint("-{calluserexit}, kframe %08x, tid %d\n", pTrapFrame, p_thread_ctx->tid);
		p_thread_ctx->va_value = 0;
		//KiUserCallbackDispatcher£¬ sysexit£¬edx
		IntKiCallUserExitCheckWait(p_thread_ctx, g_ntdll_base + 0x84640);
	}
	//HYPERPLATFORM_COMMON_DBG_BREAK();
}


VOID __stdcall IntKei386HelperExitHandler(PKTRAP_FRAME pTrapFrame)
{
	if (g_target_pid != (ULONG)PsGetCurrentProcessId())
	{
		return;
	}
	thread_ctx_t *p_thread_ctx = GET_THREAD_CTX();
	if (p_thread_ctx && p_thread_ctx->start && (pTrapFrame->SegCs != 8))
	{
		if (pTrapFrame->Eip == (g_ntdll_base + 0x845d0))      //ntdll!KiUserApcDispatcher
		{
			DbgPrint("-{i386exit} APC. thread %d, kframe esp %x, dbgeip %08x\n", p_thread_ctx->tid,
				 pTrapFrame->HardwareEsp, pTrapFrame->DbgEip);
			p_thread_ctx->va_value = 0;
			IntKiServiceCheckWait(p_thread_ctx, pTrapFrame);
		}
		else if (pTrapFrame->Eip == (g_ntdll_base + 0x84690)) //ntdll!KiUserExceptionDispatcher
		{
			DbgPrint("-{i386exit} EXCEPT. thread %d, kframe esp %x, eip %08x\n", p_thread_ctx->tid,
				pTrapFrame->HardwareEsp, pTrapFrame->Eip);
			p_thread_ctx->va_value = 0;
			IntKiServiceCheckWait(p_thread_ctx, pTrapFrame);
		}
		else if (pTrapFrame->Eip == (g_user32_base + 0x6BC0)) //user32!__ClientThreadSetup
		{
			DbgPrint("-{i386exit} USER32. thread %d, kframe esp %x, eip %08x\n", p_thread_ctx->tid,
				pTrapFrame->HardwareEsp, pTrapFrame->Eip);
			p_thread_ctx->va_value = 0;
			IntKiServiceCheckWait(p_thread_ctx, pTrapFrame);
		}
		else if (pTrapFrame->DbgEip != pTrapFrame->Eip)       //ntdll!NtContinue
		{
			DbgPrint("-{i386exit} CONT. thread %d, kframe esp %x, dbgeip %08x, eip %08x\n",
				p_thread_ctx->tid, pTrapFrame->HardwareEsp,
				pTrapFrame->DbgEip, pTrapFrame->Eip);
			p_thread_ctx->va_value = 0;
			IntKiServiceCheckWait(p_thread_ctx, pTrapFrame);
		}
		else //trap
		{
			FAULT_PROFILER *pLastProfiler = (FAULT_PROFILER *)*(ULONG *)(p_thread_ctx->teb + TEB_PROFILER_OFFSET);
			if (pLastProfiler && (pLastProfiler->Syscall == LOG_SYSENTER_FLAG))
			{
				DbgPrint("-{i386exit} TRAP. thread %d, kframe esp %x, va_value %08x, %08x\n",
					p_thread_ctx->tid, pTrapFrame->HardwareEsp,
					p_thread_ctx->va_value, pTrapFrame->Eip);
			}
			if (p_thread_ctx->va_value)
			{	
				DbgPrint("-{i386exit} CHECK. thread %d, kframe esp %x, va_value %08x, %08x\n",
					p_thread_ctx->tid, pTrapFrame->HardwareEsp,
					p_thread_ctx->va_value, pTrapFrame->Eip);
				p_thread_ctx->va_value = 0;
			}
		}
	}
}

void __stdcall IntKiTrapCheckStubHandler(PKEPT_JUMP_FRAME pTrapFrame)
{
	thread_ctx_t *p_thread_ctx = (thread_ctx_t *)pTrapFrame->HardwareSegSs;
	ProcessorData *processor_data = processor_list[KeGetCurrentProcessorNumber()];

	DbgPrint("%d {FaultPage} eip %08x, ebp %08x, ebx %08x, ecx %08x, edi %08x. pTrapFrame %08x. in_buffer %x, out_buffer %x\n",
		p_thread_ctx->tid, pTrapFrame->Eip, pTrapFrame->Ebp, pTrapFrame->Ebx, pTrapFrame->Ecx,
		pTrapFrame->Edi, pTrapFrame,
		p_thread_ctx->in_buffer->base, p_thread_ctx->out_buffer->base);

	HYPERPLATFORM_COMMON_DBG_BREAK();
}

PVOID __stdcall GetAllocBlockProfiler(ProcessorData *processorData, ULONG  faultIp)
{
	ULONG virtualPageNum = faultIp >> 12;
	ULONG  codePage = (ULONG)g_code_table[virtualPageNum];

	if (((ULONG)codePage & 0xFFF00000) == ANALYSIS_CODE_FAULT_BASE)
	{
		codePage = (ULONG)AllocateFromUserSpaceCache(PAGE_SIZE * 4);
		for (ULONG i = 0; i < PAGE_SIZE; i++)
		{
			((PULONG)codePage)[i] = (faultIp & 0xFFFFF000) + i;
		}
		//concurrence?
		ULONG initCodePage = ANALYSIS_CODE_FAULT_BASE + virtualPageNum;
		ULONG oldCodePage = InterlockedCompareExchange((LONG *)(g_code_table + virtualPageNum), 
			(LONG)(codePage & 0xFFFFF000), initCodePage);
		if (oldCodePage == initCodePage)
		{
			g_exec_count2++;
		}
		else
		{
			DbgPrint("[GetAllocBlockProfiler] Concurrency, faultIp %x, oldCodePage %x, codePage %x\n",
				faultIp, oldCodePage, codePage);
			codePage = oldCodePage;	
		}
	}

	ULONG           mapAddr = codePage + (faultIp & 0xFFF) * 4;
	ULONG           existedCodeBase = *(ULONG *)mapAddr; 
	BLOCK_PROFILER *pProfiler = NULL;

	if (existedCodeBase != faultIp) 
	{
		pProfiler = (BLOCK_PROFILER *)*(ULONG *)(existedCodeBase + 5); //nop word ptr [eax+eax+77662211h] 
	}
	else 
	{
		if (((ULONG)processorData->hdbuf_ptr + 0x100) > (processorData->hdbuf_base + PER_CPU_HEAD_BUF_SIZE))
		{
			DbgPrint("[CHECK] GetAllocBlockProfiler. HdBufBase %x, HdBufPtr %x %x\n",
				processorData->hdbuf_base, processorData->hdbuf_ptr);
			__debugbreak();
			ZwTerminateProcess(NtCurrentProcess(), 1);
		}
		pProfiler = (BLOCK_PROFILER *)processorData->hdbuf_ptr;
		memset(pProfiler, 0, sizeof(BLOCK_PROFILER));
		pProfiler->FaultIp = faultIp;
		//stub
		UCHAR *pStubCode = (UCHAR *)((ULONG)processorData->hdbuf_ptr + sizeof(BLOCK_PROFILER));
		*(UINT8 *)(pStubCode) = 0xE9;                   //jmp  OriginBlockIp;
		*(UINT32 *)(pStubCode + 1) = faultIp - ((ULONG)pStubCode) - 5;
		*(UINT32 *)(pStubCode + 5) = (UINT32)pProfiler;

		existedCodeBase = InterlockedCompareExchange((LONG *)mapAddr, (LONG)pStubCode, faultIp);
		if (existedCodeBase == faultIp)
		{
			processorData->hdbuf_ptr += sizeof(BLOCK_PROFILER) + 9;
			KeInitializeSpinLock(&pProfiler->Lock);
		}
		else
		{
			pProfiler = (BLOCK_PROFILER *)*(ULONG *)(existedCodeBase + 5);
		}
		if ((LONG *)mapAddr == 0)
		{
			DbgPrint("GetAllocBlockProfiler check, mapAddr %x, faultIp %x, existedCodeBase %x\n", 
				mapAddr, faultIp, existedCodeBase);
		}
	}

	return pProfiler;
}

UCHAR *__stdcall OpBufferPartRecordContext(UCHAR *codePtr, ULONG all = 0)
{
	//esp
	*(UINT32 *)(codePtr) = 0x74258964;      //mov fs:[74h], esp
	*(UINT32 *)(codePtr + 4) = 0x64000000;  //mov esp, fs:[1000h]
	*(UINT32 *)(codePtr + 8) = 0x1000258B;
	*(UINT16 *)(codePtr + 12) = 0x0000;
	codePtr += 14;

	*(UINT32 *)(codePtr) = 0x53525150;    //push eax/ecx/edx/ebx/ebp/esi/edi
	*(UINT32 *)(codePtr + 4) = 0x575655;
	codePtr += 7;

	if (all)
	{
		*(UINT32 *)(codePtr) = 0x00258964;     //mov fs:[1000h], esp
		*(UINT32 *)(codePtr + 4) = 0x64000010; //mov esp, fs:[74h]
		*(UINT32 *)(codePtr + 8) = 0x0074258B;
		*(UINT16 *)(codePtr + 12) = 0x0000;
		codePtr += 14;
	}

	return codePtr;
}

UCHAR *__stdcall OpBufferRecordEflags(UCHAR *codePtr)
{
	*(UINT32 *)(codePtr) = 0x74258964;      //mov fs:[74h], esp
	*(UINT32 *)(codePtr + 4) = 0x64000000;  //mov esp, fs:[1000h]
	*(UINT32 *)(codePtr + 8) = 0x1000258B;
	*(UINT16 *)(codePtr + 12) = 0x0000;
	*(UINT8 *)(codePtr + 14) = 0x9C;        //pushfd
	*(UINT32 *)(codePtr + 15) = 0x00258964; //mov fs:[1000h], esp
	*(UINT32 *)(codePtr + 19) = 0x64000010; //mov esp, fs:[74h]
	*(UINT32 *)(codePtr + 23) = 0x0074258B;
	*(UINT16 *)(codePtr + 27) = 0x0000;
	codePtr += 29;

	return codePtr;
}

UCHAR *__stdcall OpBufferPartRecordReg(UCHAR *codePtr, UCHAR trans, ULONG full)
{
	*(UINT32 *)(codePtr) = 0x74258964;         //mov fs:[74h], esp
	*(UINT32 *)(codePtr + 4) = 0x64000000;     //mov esp, fs:[1000h]
	*(UINT32 *)(codePtr + 8) = 0x1000258B;
	*(UINT16 *)(codePtr + 12) = 0x0000;

	if (trans == 0x54)          //push  esp
	{
		*(UINT32 *)(codePtr + 14) = 0x7435FF64; //push fs:[74h]
		*(UINT32 *)(codePtr + 18) = 0x000000;
		codePtr += 21;
	}
	else
	{
		*(UINT8 *)(codePtr + 14) = trans;      //push  REG
		codePtr += 15;
	}
	

	if (full)
	{
		*(UINT32 *)(codePtr) = 0x00258964;     //mov fs:[1000h], esp
		*(UINT32 *)(codePtr + 4) = 0x64000010; //mov esp, fs:[74h]
		*(UINT32 *)(codePtr + 8) = 0x0074258B;
		*(UINT16 *)(codePtr + 12) = 0x0000;
		codePtr += 14;
	}

	return codePtr;
}

UCHAR *__stdcall OpBufferRecordEflagsReg(UCHAR *codePtr, ud_t *pUdObj, ULONG oprIndx)
{
	const   ud_operand_t* opr = &pUdObj->operand[oprIndx];

	*(UINT32 *)(codePtr) = 0x74258964;      //mov fs:[74h], esp
	*(UINT32 *)(codePtr + 4) = 0x64000000;  //mov esp, fs:[1000h]
	*(UINT32 *)(codePtr + 8) = 0x1000258B;
	*(UINT32 *)(codePtr + 12) = 0x9C0000;   //pushfd
	codePtr += 15;

	*(UINT8 *)(codePtr) = opr->base + 43;   //push reg
	codePtr += 1;
	
	*(UINT32 *)(codePtr) = 0x00258964;      //mov fs:[1000h], esp
	*(UINT32 *)(codePtr + 4) = 0x64000010;  //mov esp, fs:[74h]
	*(UINT32 *)(codePtr + 8) = 0x0074258B;
	*(UINT16 *)(codePtr + 12) = 0x0000;
	codePtr += 14;

	return codePtr;
}

UCHAR *__stdcall OpBufferPartRecordEcxEdi(UCHAR *codePtr, ULONG full)
{
	*(UINT32 *)(codePtr) = 0x74258964;      //mov fs:[74h], esp
	*(UINT32 *)(codePtr + 4) = 0x64000000;  //mov esp, fs:[1000h]
	*(UINT32 *)(codePtr + 8) = 0x1000258B;
	*(UINT32 *)(codePtr + 12) = 0x57510000;  //push ecx; push edi
	codePtr += 16;

	if (full)
	{
		*(UINT32 *)(codePtr) = 0x00258964;      //mov fs:[1000h], esp
		*(UINT32 *)(codePtr + 4) = 0x64000010;  //mov esp, fs:[74h]
		*(UINT32 *)(codePtr + 8) = 0x0074258B;
		*(UINT16 *)(codePtr + 12) = 0x0000;
		codePtr += 14;
	}

	return codePtr;
}

UCHAR *__stdcall OpBufferPartRecordEcxEdiEflags(UCHAR *codePtr, ULONG full)
{
	*(UINT32 *)(codePtr) = 0x74258964;       //mov fs:[74h], esp
	*(UINT32 *)(codePtr + 4) = 0x64000000;   //mov esp, fs:[1000h]
	*(UINT32 *)(codePtr + 8) = 0x1000258B;
	*(UINT32 *)(codePtr + 12) = 0x57510000;  //push ecx; push edi
	*(UINT8 *)(codePtr + 16) = 0x9C;         //pushfd
	codePtr += 17;

	if (full)
	{
		*(UINT32 *)(codePtr) = 0x00258964;      //mov fs:[1000h], esp
		*(UINT32 *)(codePtr + 4) = 0x64000010;  //mov esp, fs:[74h]
		*(UINT32 *)(codePtr + 8) = 0x0074258B;
		*(UINT16 *)(codePtr + 12) = 0x0000;
		codePtr += 14;
	}

	return codePtr;
}

UCHAR *__stdcall OpBufferPartRecordEcxEsiEdi(UCHAR *codePtr, ULONG full)
{
	*(UINT32 *)(codePtr) = 0x74258964;      //mov fs:[74h], esp
	*(UINT32 *)(codePtr + 4) = 0x64000000;  //mov esp, fs:[1000h]
	*(UINT32 *)(codePtr + 8) = 0x1000258B;
	*(UINT32 *)(codePtr + 12) = 0x56510000; //push ecx; push esi; 
	*(UINT8 *)(codePtr + 16) = 0x57;        //push edi
	codePtr += 17;

	if (full)
	{
		*(UINT32 *)(codePtr) = 0x00258964;      //mov fs:[1000h], esp
		*(UINT32 *)(codePtr + 4) = 0x64000010;  //mov esp, fs:[74h]
		*(UINT32 *)(codePtr + 8) = 0x0074258B;
		*(UINT16 *)(codePtr + 12) = 0x0000;
		codePtr += 14;
	}

	return codePtr;
}

UCHAR *__stdcall OpBufferPartRecordEcxEsiEdiEflags(UCHAR *codePtr, ULONG full)
{
	*(UINT32 *)(codePtr) = 0x74258964;      //mov fs:[74h], esp
	*(UINT32 *)(codePtr + 4) = 0x64000000;  //mov esp, fs:[1000h]
	*(UINT32 *)(codePtr + 8) = 0x1000258B;
	*(UINT32 *)(codePtr + 12) = 0x56510000; //push ecx; push esi; 
	*(UINT16 *)(codePtr + 16) = 0x9C57;        //push edi; pushfd
	codePtr += 18;

	if (full)
	{
		*(UINT32 *)(codePtr) = 0x00258964;      //mov fs:[1000h], esp
		*(UINT32 *)(codePtr + 4) = 0x64000010;  //mov esp, fs:[74h]
		*(UINT32 *)(codePtr + 8) = 0x0074258B;
		*(UINT16 *)(codePtr + 12) = 0x0000;
		codePtr += 14;
	}

	return codePtr;
}

UCHAR *__stdcall OpBufferPartRecordEax(UCHAR *codePtr, ULONG full)
{
	*(UINT32 *)(codePtr) = 0x74258964;       //mov fs:[74h], esp
	*(UINT32 *)(codePtr + 4) = 0x64000000;   //mov esp, fs:[1000h]
	*(UINT32 *)(codePtr + 8) = 0x1000258B;
	*(UINT16 *)(codePtr + 12) = 0x0000;
	*(UINT8 *)(codePtr + 14) = 0x50;         //push eax
	codePtr += 15;

	if (full)
	{
		*(UINT32 *)(codePtr) = 0x00258964;     //mov fs:[1000h], esp
		*(UINT32 *)(codePtr + 4) = 0x64000010; //mov esp, fs:[74h]
		*(UINT32 *)(codePtr + 8) = 0x0074258B;
		*(UINT16 *)(codePtr + 12) = 0x0000;
		codePtr += 14;
	}
	
	return codePtr;
}

UCHAR *__stdcall OpBufferPartRecordEaxEdx(UCHAR *codePtr, ULONG full)
{
	*(UINT32 *)(codePtr) = 0x74258964;       //mov fs:[74h], esp
	*(UINT32 *)(codePtr + 4) = 0x64000000;   //mov esp, fs:[1000h]
	*(UINT32 *)(codePtr + 8) = 0x1000258B;
	*(UINT16 *)(codePtr + 12) = 0x0000;
	*(UINT16 *)(codePtr + 14) = 0x5250;      //push eax; push edx
	codePtr += 16;

	if (full)
	{
		*(UINT32 *)(codePtr) = 0x00258964;      //mov fs:[1000h], esp
		*(UINT32 *)(codePtr + 4) = 0x64000010;  //mov esp, fs:[74h]
		*(UINT32 *)(codePtr + 8) = 0x0074258B;
		*(UINT16 *)(codePtr + 12) = 0x0000;
		codePtr += 14;
	}
	
	return codePtr;
}

UCHAR *__stdcall OpBufferPartRecordEspEbp(UCHAR *codePtr, ULONG full)
{
	*(UINT32 *)(codePtr) = 0x74258964;      //mov fs:[74h], esp
	*(UINT32 *)(codePtr + 4) = 0x64000000;  //mov esp, fs:[1000h]
	*(UINT32 *)(codePtr + 8) = 0x1000258B;
	*(UINT32 *)(codePtr + 12) = 0xFF640000; //push fs:[74h]
	*(UINT32 *)(codePtr + 16) = 0x00007435;
	*(UINT16 *)(codePtr + 20) = 0x5500;     //push ebp
	codePtr += 22;

	if (full)
	{
		*(UINT32 *)(codePtr) = 0x00258964;      //mov fs:[1000h], esp
		*(UINT32 *)(codePtr + 4) = 0x64000010;  //mov esp, fs:[74h]
		*(UINT32 *)(codePtr + 8) = 0x0074258B;
		*(UINT16 *)(codePtr + 12) = 0x0000;
		codePtr += 14;
	}

	return codePtr;
}

UCHAR *__stdcall OpBufferPartRecordEcxEsiEax(UCHAR *codePtr, ULONG full)
{
	*(UINT32 *)(codePtr) = 0x74258964;       //mov fs:[74h], esp
	*(UINT32 *)(codePtr + 4) = 0x64000000;   //mov esp, fs:[1000h]
	*(UINT32 *)(codePtr + 8) = 0x1000258B;
	*(UINT16 *)(codePtr + 12) = 0x0000;
	*(UINT32 *)(codePtr + 14) = 0x505651;    //push ecx; push esi; push eax
	codePtr += 17;

	if (full)
	{
		*(UINT32 *)(codePtr) = 0x00258964;      //mov fs:[1000h], esp
		*(UINT32 *)(codePtr + 4) = 0x64000010;  //mov esp, fs:[74h]
		*(UINT32 *)(codePtr + 8) = 0x0074258B;
		*(UINT16 *)(codePtr + 12) = 0x0000;
		codePtr += 14;
	}

	return codePtr;
}

UCHAR * _stdcall OpCopyCacheCodeMid(ULONG *cflag, UCHAR *codePtr, UCHAR *cacheBase, UCHAR **pCachePtr)
{
	if ((*cflag) == 2) 
	{
		*cflag = 1; 
		*(UINT32 *)(codePtr) = 0x00258964;     //mov fs:[1000h], esp
		*(UINT32 *)(codePtr + 4) = 0x64000010; //mov esp, fs:[74h]
		*(UINT32 *)(codePtr + 8) = 0x0074258B;
		*(UINT16 *)(codePtr + 12) = 0x0000;
		codePtr += 14;
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

UCHAR * _stdcall OpCopyCacheCodeBlock(ULONG cflag, UCHAR *codePtr, UCHAR *cacheBase, UCHAR **pCachePtr)
{
	if (cflag == 2)
	{
		*(UINT32 *)(codePtr) = 0x2589649C;      //pushfd
		*(UINT32 *)(codePtr + 4) = 0x00001000;  //mov fs:[1000h], esp
		*(UINT32 *)(codePtr + 8) = 0x74258B64;  //mov esp, fs:[74h]
		*(UINT32 *)(codePtr + 12) = 0x000000;
		codePtr += 15;
	}
	else if (cflag == 1)
	{
		*(UINT32 *)(codePtr) = 0x74258964;      //mov fs:[74h], esp
		*(UINT32 *)(codePtr + 4) = 0x64000000;  //mov esp, fs:[1000h]
		*(UINT32 *)(codePtr + 8) = 0x1000258B;
		*(UINT16 *)(codePtr + 12) = 0x0000;
		*(UINT8 *)(codePtr + 14) = 0x9C;        //pushfd
		*(UINT32 *)(codePtr + 15) = 0x00258964; //mov fs:[1000h], esp
		*(UINT32 *)(codePtr + 19) = 0x64000010; //mov esp, fs:[74h]
		*(UINT32 *)(codePtr + 23) = 0x0074258B;
		*(UINT16 *)(codePtr + 27) = 0x0000;
		codePtr += 29;
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

ULONG __stdcall IntEptVoilationHandler(ProcessorData *processor_data, PKEPT_FAULT_FRAME pTrapFrame)
{
	thread_ctx_t *p_thread_ctx = GET_THREAD_CTX();
	if (!p_thread_ctx)
	{
		AsmVmFunc(0, EPTP_NORMAL);
		return 8;
	}

	if ((UCHAR)p_thread_ctx == ANALYSIS_THREAD_CTX)
	{
		DbgPrint("[#VE] Analysis execute. cpu %d, tid %d, eip %08x. gla %llx, gpa %llx. TrapFrame %x, eflags %x.\n", 
			KeGetCurrentProcessorNumber(), PsGetCurrentThreadId(), pTrapFrame->Eip, 
			processor_data->ve->gla, processor_data->ve->gpa,pTrapFrame, pTrapFrame->EFlags);
		HYPERPLATFORM_COMMON_DBG_BREAK();
		return 0;
	}
	else if (pTrapFrame->SegCs == 8)
	{
		DbgPrint("[#VE] SegCs 8. cpu %d, tid %d, eip %08x. gla %llx, gpa %llx. TrapFrame %x, eflags %x.\n",
			KeGetCurrentProcessorNumber(), PsGetCurrentThreadId(), pTrapFrame->Eip,
			processor_data->ve->gla, processor_data->ve->gpa, pTrapFrame, pTrapFrame->EFlags);
		HYPERPLATFORM_COMMON_DBG_BREAK();
		return 1;
	}
	
	processor_data->counter_0++;
	//Check bug
	if ((0x84690 + g_ntdll_base) == pTrapFrame->Eip)
	{
		DbgPrint("%d [KiUserExceptionDispatcher] esp %08x, pTrapFrame %08x.\n", p_thread_ctx->tid, pTrapFrame->HardwareEsp, pTrapFrame);
		if (*(ULONG *)(pTrapFrame->HardwareEsp + 0x14) != (0xb24c2 + g_kernel_base))
		{
			HYPERPLATFORM_COMMON_DBG_BREAK();
			ZwTerminateProcess(NtCurrentProcess(), 1);
		}
	}

	CodePageRewritingBlockLink(processor_data, p_thread_ctx, pTrapFrame);

	return 0;
}

_Use_decl_annotations_ VOID DpcContextSwitchBuffer(
	struct _KDPC  *Dpc,
	PVOID  DeferredContext,
	PVOID  SystemArgument1,
	PVOID  SystemArgument2
)
{
	thread_ctx_t *p_thread_ctx = (thread_ctx_t *)DeferredContext;

	ULONG pcr = AsmGetPcr();
	if (*(ULONG *)(pcr + KPCR_EPTP_OFFSET) == EPTP_ANALYSIS)
	{
		DbgPrint("%d [DpcContextSwitch Check] tid %x, target tid %d, in_buffer %x, curr %x\n",
			KeGetCurrentProcessorNumber(), PsGetCurrentThreadId(), p_thread_ctx->tid, p_thread_ctx->in_buffer->base,
			p_thread_ctx->in_buffer->curr);
	}

	ExInterlockedInsertTailList(&p_thread_ctx->full_list.listhead, &p_thread_ctx->in_buffer->entry,
		&p_thread_ctx->full_list.spinlock);
	KeReleaseSemaphore(&p_thread_ctx->full_list.semaphore, IO_NO_INCREMENT, 1, FALSE);
	KeSetEvent(&p_thread_ctx->in_buffer_event, IO_NO_INCREMENT, FALSE);
}

ULONG __stdcall IntSwapOutHandler(ProcessorData *processor_data, thread_ctx_t *p_thread_ctx)
{
	//IF=1, KPCR->CurrentThread = esi

	processor_data->counter_5++;

	p_thread_ctx->running = 0;

	if (p_thread_ctx->fault_pending || p_thread_ctx->in_buffer_pending || p_thread_ctx->is_last)
	{
		//if (p_thread_ctx->in_buffer_pending)
		//{
		//	 DbgPrint(" [PENDING] %d-%d, tid %d, in_buffer base %x curr %x - %x, real %x\n",
		//		p_thread_ctx->fault_pending, p_thread_ctx->in_buffer_pending,
		//		p_thread_ctx->tid, p_thread_ctx->in_buffer->base, p_thread_ctx->in_buffer->curr,
		//		*(ULONG *)p_thread_ctx->teb_extend_va, p_thread_ctx->in_buffer->real);
		//}	
		return 0;
	}
	ULONG  value = 0;

	ULONG curr = *(ULONG *)p_thread_ctx->teb_extend_va;
	if (curr <= (ULONG)p_thread_ctx->in_buffer->base)
	{
		DbgPrint(" [SKIP] tid %d, in_buffer base %x, curr %x, real %x, teb_extend_va %x\n",
			p_thread_ctx->tid, p_thread_ctx->in_buffer->base,
			p_thread_ctx->in_buffer->curr, p_thread_ctx->in_buffer->real, curr);
		return 0;
	}

	CloseInterrupt();
	p_thread_ctx->is_flush = 0;
	p_thread_ctx->in_buffer_pending = 1;

	p_thread_ctx->in_buffer->curr = (void *)curr;
	p_thread_ctx->in_buffer->real = NULL;

	p_thread_ctx->monitor_page_base = (PVOID)((ULONG)p_thread_ctx->in_buffer->curr & 0xFFFFF000);
	for (ULONG i = 0; i < 2; i++)
	{
		ULONG page = (ULONG)p_thread_ctx->monitor_page_base + i * PAGE_SIZE;
		if ((PVOID)page == p_thread_ctx->in_buffer->limit)
		{
			break;
		}
		PHYSICAL_ADDRESS lpa = MmGetPhysicalAddress((PVOID)page);
		//DbgPrint("   monitor_page %x, %llx\n", page, lpa.QuadPart);
		//__invlpg((PVOID)page);
		UpdateEptEntry(g_shared_data->ept_data_list[EPTP_MONITOR1], lpa.QuadPart, 1);
	}
	StartInterrupt();
	KeIpiGenericCall(&IpiEptMonitorSwapContext, (ULONG_PTR)p_thread_ctx);

	p_thread_ctx->is_flush = 1;
	//DPC
	ULONG dpcTargetNum = (KeGetCurrentProcessorNumber() + 1) % 4;
	processor_data->counter_3++;
	KeSetTargetProcessorDpc(&p_thread_ctx->dpc_c, dpcTargetNum);
	KeInsertQueueDpc(&p_thread_ctx->dpc_c, NULL, NULL);

	return 0;
}

_Use_decl_annotations_ void ApcFaultRequireBuffer(PVOID NormalContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
	thread_ctx_t *p_thread_ctx = (thread_ctx_t *)NormalContext;

	if (p_thread_ctx->need_set)
	{
		ULONG  lastBufPtr = *(ULONG *)p_thread_ctx->teb_extend_va;
		*(ULONG *)(lastBufPtr - 4) = g_checkCodePage + 12; 

		p_thread_ctx->need_set = 0;
	}
	else if (p_thread_ctx->need_check)
	{
		ULONG  lastBufPtr = *(ULONG *)p_thread_ctx->teb_extend_va;
		*(ULONG *)(lastBufPtr - 4) = g_checkCodePage;

		p_thread_ctx->need_check = 0;
	}

	ULONG pcr = AsmGetPcr();
	if (*(ULONG *)(pcr + KPCR_EPTP_OFFSET) == EPTP_ANALYSIS)
	{
		DbgPrint("%d [APC_FAULT¡¡Check] tid %d, ethread %x, in_buffer %x, curr %x, real %x\n",
			KeGetCurrentProcessorNumber(),p_thread_ctx->tid, p_thread_ctx->ethread, 
			p_thread_ctx->in_buffer->base, p_thread_ctx->in_buffer->curr, p_thread_ctx->in_buffer->real);
	}
	//DbgPrint(" [APC_FAULT_REQUIRE] tid %d, ethread %x, in_buffer %x %x %x\n",
	//	p_thread_ctx->tid, p_thread_ctx->ethread, p_thread_ctx->in_buffer->base, 
	//	p_thread_ctx->in_buffer->curr, p_thread_ctx->in_buffer->real);
	
	if (p_thread_ctx->in_buffer_pending)
	{
		KeWaitForSingleObject(&p_thread_ctx->in_buffer_event, Executive, KernelMode, FALSE, NULL);
	}
	
	KeWaitForSingleObject(&p_thread_ctx->free_list.semaphore, Executive, KernelMode, FALSE, NULL);
	p_thread_ctx->in_buffer = (LIST_ELEMENT *)ExInterlockedRemoveHeadList(&p_thread_ctx->free_list.listhead,
		&p_thread_ctx->free_list.spinlock);
	p_thread_ctx->in_buffer->entry.Flink = NULL;
	p_thread_ctx->in_buffer->entry.Blink = NULL;
	p_thread_ctx->in_buffer->curr = NULL;
	p_thread_ctx->in_buffer->real = NULL;
	p_thread_ctx->in_buffer_pending = 0;
}

_Use_decl_annotations_ VOID DpcFaultSwitchBuffer(
	struct _KDPC  *Dpc,
	PVOID  DeferredContext,
	PVOID  SystemArgument1,
	PVOID  SystemArgument2
)
{
	thread_ctx_t *p_thread_ctx = (thread_ctx_t *)DeferredContext;
	
	ULONG pcr = AsmGetPcr();
	if (*(ULONG *)(pcr + KPCR_EPTP_OFFSET) == EPTP_ANALYSIS)
	{
		DbgPrint("%d [DpcFaultSwitch Check] tid %d, in_buffer_base %x, curr %x, real %x, monitor_page %x\n",
			KeGetCurrentProcessorNumber(), p_thread_ctx->tid, p_thread_ctx->in_buffer->base,
			p_thread_ctx->in_buffer->curr, SystemArgument1, p_thread_ctx->monitor_page_base);
	}

	if (!p_thread_ctx->in_buffer_pending)
	{
		p_thread_ctx->in_buffer->curr = SystemArgument1; 
		p_thread_ctx->in_buffer->real = p_thread_ctx->in_buffer->curr;
		ExInterlockedInsertTailList(&p_thread_ctx->full_list.listhead, &p_thread_ctx->in_buffer->entry,
			&p_thread_ctx->full_list.spinlock);
		KeReleaseSemaphore(&p_thread_ctx->full_list.semaphore, IO_NO_INCREMENT, 1, FALSE);
	}
	else
	{
		CloseInterrupt();
		p_thread_ctx->in_buffer->real = SystemArgument1;
		for (ULONG i = 0; i < 2; i++)
		{
			ULONG  page = (ULONG)p_thread_ctx->monitor_page_base + i * PAGE_SIZE;
			if ((PVOID)page == p_thread_ctx->in_buffer->limit)
			{
				break;
			}
			PHYSICAL_ADDRESS  lpa = MmGetPhysicalAddress((PVOID)page);
			UpdateEptEntry(g_shared_data->ept_data_list[EPTP_MONITOR1], lpa.QuadPart, 3);	
		}	
		StartInterrupt();
		KeIpiGenericCall(&IpiEptMonitorPendingFault, (ULONG_PTR)p_thread_ctx);
		p_thread_ctx->monitor_page_base = NULL;
	}
	
	BOOLEAN  status = KeInsertQueueApc(&p_thread_ctx->apc_f, NULL, NULL, 0);

	//DbgPrint(" [DPC_FAULT] tid %d, in_buffer %x curr %x, insert_apc %u\n", p_thread_ctx->tid, p_thread_ctx->in_buffer->base,
	//	p_thread_ctx->in_buffer->curr, status);
}


ULONG __stdcall IntEptCommonHandler(ProcessorData *processor_data, PKEPT_JUMP_FRAME pTrapFrame)
{
	const EptViolationQualification exit_qualification = { processor_data->ve->exit };

	if (!(exit_qualification.all & 0x38)) 
	{
		UtilVmCall(HypercallNumber::kHandleEptVoilation, &processor_data->ve->gpa);	
		return 0;
	}
	else if (exit_qualification.all & 2) 
	{
		thread_ctx_t *p_thread_ctx = GET_THREAD_CTX();
		if (!p_thread_ctx)
		{
			EptPtEntry *ept_entry1 = (EptPtEntry *)EptGetEptPtEntry(g_shared_data->ept_data_list[EPTP_MONITOR1], processor_data->ve->gpa);
			EptPtEntry *ept_entry2 = (EptPtEntry *)EptGetEptPtEntry(g_shared_data->ept_data_list[EPTP_ANALYSIS], processor_data->ve->gpa);
			/*DbgPrint("[Check] WaitStubHandlerWrite. cpu %d, tid %d, write %llx %llx, entry %x, %x, eip %08x, TrapFrame %x.\n",
				KeGetCurrentProcessorNumber(), PsGetCurrentThreadId(), processor_data->ve->gla, 
				processor_data->ve->gpa, ept_entry1, ept_entry2, pTrapFrame->Eip, pTrapFrame);*/
			ept_entry1->fields.write_access = 1;
			ept_entry2->fields.write_access = 1;
			__invlpg((PVOID)processor_data->ve->gla);

			return 0;
		}
		if ((UCHAR)p_thread_ctx == ANALYSIS_THREAD_CTX)
		{
			DbgPrint("[Check] WaitStubHandlerWrite. cpu %d, tid %d, write %llx %llx, eip %08x, TrapFrame %x.\n",
				KeGetCurrentProcessorNumber(), PsGetCurrentThreadId(), processor_data->ve->gla,
				processor_data->ve->gpa,pTrapFrame->Eip, pTrapFrame);
		}
		processor_data->counter_6++;
		InterlockedExchange((LONG *)&p_thread_ctx->fault_pending, 1);
		//DPC -> APC
		KeInsertQueueDpc(&p_thread_ctx->dpc_f, (PVOID)processor_data->ve->gla, NULL);  
		InterlockedExchange((LONG *)&p_thread_ctx->fault_pending, 0);
		//mov, solution
		UCHAR fByteCode = *(UINT8 *)pTrapFrame->Eip;
		ULONG offset;
		if ((fByteCode == 0x89) || ((fByteCode == 0xC7)))    //mov  [eax + off], ebx/IMM
		{
			UCHAR sByteMask = (*(UINT8 *)(pTrapFrame->Eip + 1)) & 7;	
			if (sByteMask == 0)     //C7 80
			{
				offset = *(UINT32 *)(pTrapFrame->Eip + 2);
				pTrapFrame->Eax = (ULONG)p_thread_ctx->in_buffer->base - offset;
			}
			else if (sByteMask == 2) //C7 82
			{
				offset = *(UINT32 *)(pTrapFrame->Eip + 2);
				pTrapFrame->Edx = (ULONG)p_thread_ctx->in_buffer->base - offset;
			}
			else if (sByteMask == 3) //C7 83
			{
				offset = *(UINT32 *)(pTrapFrame->Eip + 2);
				pTrapFrame->Ebx = (ULONG)p_thread_ctx->in_buffer->base - offset;
			}
			else if (sByteMask == 4) //C7 84 24
			{
				offset = *(UINT32 *)(pTrapFrame->Eip + 3);
				pTrapFrame->HardwareEsp = (ULONG)p_thread_ctx->in_buffer->base - offset;
			}
		}
		else if (fByteCode == 0x0F)  //setcc [eax + 8]
		{
			offset = *(UINT32 *)(pTrapFrame->Eip + 3);
			pTrapFrame->Eax = (ULONG)p_thread_ctx->in_buffer->base - offset;
		}
		else if (fByteCode == 0x9C)  //pushfd
		{
			offset = *(UINT32 *)(pTrapFrame->Eip - 4) - 4;
			pTrapFrame->HardwareEsp = (ULONG)p_thread_ctx->in_buffer->base + 4;
		}
		*(ULONG *)p_thread_ctx->teb_extend_va = (ULONG)p_thread_ctx->in_buffer->base - offset;
	}
	else
	{
		thread_ctx_t *p_thread_ctx = GET_THREAD_CTX();
		if ((UCHAR)p_thread_ctx == ANALYSIS_THREAD_CTX)
		{
			PVOID pethread = PsGetCurrentThread();
			if (processor_data->ve->gla == (g_checkCodePage + 4))
			{
				DbgPrint(" {READ_FAULT} enter. tid %d, eip %08x, flag_addr %llx.\n",
					PsGetCurrentThreadId(), pTrapFrame->Eip, processor_data->ve->gla);
				*(USHORT *)((PUCHAR)pethread + CTX_OFFSET) = 0xBBAA;
				pTrapFrame->Eip += 3;
			}
			else if (processor_data->ve->gla == (g_checkCodePage + 8))
			{
				DbgPrint(" {READ_FAULT} exit. tid %d, eip %08x, flag_addr %llx.\n",
					PsGetCurrentThreadId(), pTrapFrame->Eip, processor_data->ve->gla);
				DbgPrint("   CONTEXT. %x %x %x, %x %x %x %x.\n", pTrapFrame->Edi, pTrapFrame->Esi,
					pTrapFrame->Ebp, pTrapFrame->Ebx, pTrapFrame->Edx, pTrapFrame->Ecx, pTrapFrame->Eax);
				*(USHORT *)((PUCHAR)pethread + CTX_OFFSET) = 0x00AA;
				pTrapFrame->Eip += 3;
			}
			else if (processor_data->ve->gla == (g_checkCodePage + 12))
			{
				p_thread_ctx = (thread_ctx_t *)pTrapFrame->HardwareSegSs;
				ULONG param_addr = (ULONG)p_thread_ctx->set_buffer + (p_thread_ctx->set_count++) * 8;
				ULONG buf = *(ULONG *)param_addr;
				ULONG len = *(ULONG *)(param_addr + 4);

				for (ULONG i = 0; i < len; i++)
				{
					ULONG va = (ULONG)buf + i;
					BUFFER_ENTRY *entry = (BUFFER_ENTRY *)g_entry_table[va >> 12];
					if (!entry)
					{
						DbgPrint("[SET_FAULT] null entry, tid %d, va %x\n", PsGetCurrentThreadId(), va);
						HYPERPLATFORM_COMMON_DBG_BREAK();
					}
					ULONG map_va = (ULONG)entry->Address + (va & 0xFFF);
					*(UINT8 *)map_va = 1;
				}
				pTrapFrame->Eip += 2;

				DbgPrint("{SET_FAULT}. tid %d, eip %08x, flag_addr %llx, buf %x, len %u.\n",
					PsGetCurrentThreadId(), pTrapFrame->Eip, processor_data->ve->gla, buf, len);
			}
			else
			{
				p_thread_ctx = (thread_ctx_t *)pTrapFrame->HardwareSegSs;
				ULONG param_addr = (ULONG)p_thread_ctx->check_buffer + (p_thread_ctx->check_count++) * 8;
				ULONG buf = *(ULONG *)param_addr;
				ULONG len = *(ULONG *)(param_addr + 4);
				ULONG tainted = 0;
				for (ULONG i = 0; i < len; i++)
				{
					ULONG  va = buf + i;
					BUFFER_ENTRY *map_entry = (BUFFER_ENTRY *)g_entry_table[va >> 12];
					if (!map_entry)
					{
						DbgPrint("[CHECK_FAULT] null entry, tid %d, va %x\n", PsGetCurrentThreadId(), va);
						HYPERPLATFORM_COMMON_DBG_BREAK();
					}
					ULONG map_va = (ULONG)map_entry->Address + (va & 0xFFF);
					if (*(UINT8 *)map_va)
					{
						tainted++;
					}
				}
				pTrapFrame->Eip += 2;

				//if (tainted)
				//{
				//	//Check all
				//	for (ULONG vfn = 0; vfn < 0x80000; vfn++)
				//	{

				//	}
				//}

				DbgPrint("{CHECK_FAULT}. tid %d, eip %08x, flag_addr %llx, buf %x, len %u, tainted %u.\n",
					PsGetCurrentThreadId(), pTrapFrame->Eip, processor_data->ve->gla, buf, len, tainted);
			}	
			
			return 0;
		}
		else
		{
			if (processor_data->ve->gla == g_checkCodePage + 0x100)
			{		
				//g_gdi32ExtTextOutW
				ULONG buf = *(ULONG *)(pTrapFrame->HardwareEsp + 4 * 6);
				ULONG len = *(ULONG *)(pTrapFrame->HardwareEsp + 4 * 7);

				//g_notepad_7955
				/*ULONG buf = *(ULONG *)(pTrapFrame->HardwareEsp - 8);
				ULONG len = *(ULONG *)(pTrapFrame->HardwareEsp - 4);*/

				ULONG p = (ULONG)p_thread_ctx->check_ptr;
				*(ULONG *)(p) = (ULONG)buf;
				*(ULONG *)(p + 4) = len * 2;
				p_thread_ctx->check_ptr = (PVOID)(p + 8);

				DbgPrint("[TAINT] Check point usermode, tid %d, buf %x, len %u.\n", PsGetCurrentThreadId(),buf, len);

				pTrapFrame->Eip += 5;
			}
			else
			{
				HYPERPLATFORM_COMMON_DBG_BREAK();
				DbgPrint("Check read #VE. cpu %d, tid %d, eip %08x, gla %llx, gpa %llx. exit %llx, TrapFrame %x, eflags %x.\n", KeGetCurrentProcessorNumber(),
					PsGetCurrentThreadId(), pTrapFrame->Eip, processor_data->ve->gla, processor_data->ve->gpa,
					exit_qualification.all, pTrapFrame, pTrapFrame->EFlags);
			}		
		}
	}
	return 0;
}

void __stdcall  MySwapOutHandler(PVOID kpcr, PVOID old_ethread, PVOID new_ethread, PVOID eflags)
{
	DbgPrint(" [ANALYSIS_THREAD_OUT] cpu %d, fs_c_thread %x, old_ethread %x, new_ethread %x, eflags %x\n",
		KeGetCurrentProcessorNumber(), KeGetCurrentThread(), old_ethread, new_ethread, eflags);
}

void __stdcall  MySwapInHandler1(PVOID kpcr, PVOID ethread)
{
	ULONG        tid = *(ULONG *)((PUCHAR)ethread + 0x378);
	ULONG        eptp = *(ULONG *)((ULONG)kpcr + KPCR_EPTP_OFFSET);

	DbgPrint(" [ANALYSIS_THREAD_IN] cpu %d, eptp %d, tid %d, ethread %x\n", 
		KeGetCurrentProcessorNumber(), eptp, tid, ethread);
}

void __stdcall  MySwapInHandler2(PVOID kpcr, PVOID ethread, thread_ctx_t *p_thread_ctx)
{
	p_thread_ctx->running = 1;
	if (p_thread_ctx->in_buffer_pending)
	{
		if (!p_thread_ctx->is_flush)
		{
			DbgPrint(" [TARGET_THREAD_IN] cpu %d, in_buffer_pending, base %x, curr %x, real %x, cpu %d, tid %d, ethread %x\n",
				KeGetCurrentProcessorNumber(), p_thread_ctx->in_buffer->base, p_thread_ctx->in_buffer->curr,
				p_thread_ctx->in_buffer->real, p_thread_ctx->tid, ethread);
		}	
	}
}

ULONG __stdcall IntTargetThreadPageFaultHandler(ULONG faultAddr,  KBITMAP_FAULT_FRAME *pFaultFrame)
{
	if ((faultAddr >= ANALYSIS_CODE_FAULT_BASE) &&
		(faultAddr < (ANALYSIS_CODE_FAULT_BASE + 0x80000)))
	{
		pFaultFrame->Ecx = (pFaultFrame->Ecx << 12) + pFaultFrame->Edx; 
		pFaultFrame->Eip = pFaultFrame->Eip + 3;
	}
	
	return 0;
}

void __stdcall  MyIdtHandler1(ULONG idtVec, PVOID retAddr)
{
	DbgPrint("[MyIdtHandler1] tid %d, %x, cpu %d, idtVec %x, retAddr %x\n",
		PsGetCurrentThreadId(), PsGetCurrentThread(), KeGetCurrentProcessorNumber(), idtVec, retAddr);
}

void __stdcall  MyIdtHandler2(ULONG eflag, PVOID retAddr)
{
	DbgPrint("[MyIdtHandler2] tid %d, %x, cpu %d, eflag %x, restore addr %x\n",
		PsGetCurrentThreadId(), PsGetCurrentThread(), KeGetCurrentProcessorNumber(), eflag, retAddr);
}

void __stdcall MyDebugPrint1(ULONG ebp)
{
	DbgPrint("[MyDebugPrint1] tid %d, ebp %x\n", PsGetCurrentThreadId(), ebp);
}

VOID AssistedAnalysisThread(PVOID lpParam)
{
	thread_ctx_t *p_thread_ctx = (thread_ctx_t *)lpParam;

	PETHREAD   ethread = PsGetCurrentThread();

	//KeSetPriorityThread(PsGetCurrentThread(), LOW_PRIORITY);
	KPRIORITY  prior = KeQueryPriorityThread(ethread);
	DbgPrint("<AssistedThreadCreate> for %d. TID %d, ETHREAD %x, prior %d.\n",
		p_thread_ctx->tid, PsGetCurrentThreadId(), PsGetCurrentThread(), prior);

	InterlockedIncrement((LONG *)&g_athread_count);

	KeWaitForSingleObject(&p_thread_ctx->full_list.semaphore, Executive, KernelMode, FALSE, NULL);
	p_thread_ctx->out_buffer = (LIST_ELEMENT *)ExInterlockedRemoveHeadList(&p_thread_ctx->full_list.listhead,
		&p_thread_ctx->full_list.spinlock);

	DbgPrint(" <Analysis start for %d, ctx_state %x, analysis_base %08x, first_buffer %08x, %08x, %08x, %08x\n",
		p_thread_ctx->tid, p_thread_ctx->ctx_state, p_thread_ctx->analysis_base, 
		p_thread_ctx->out_buffer->base, p_thread_ctx->out_buffer->curr, p_thread_ctx->out_buffer->real,
		p_thread_ctx->out_buffer->limit);

	KAPC_STATE  kApc;
	KeStackAttachProcess((PEPROCESS)g_target_eprocess, &kApc);

	*(UCHAR *)((PUCHAR)ethread + CTX_OFFSET) = ANALYSIS_THREAD_CTX;
	
	AsmEnterIntoAnalysisCode(p_thread_ctx->analysis_base, p_thread_ctx->out_buffer->base, 
		p_thread_ctx->out_buffer->curr, (PVOID)p_thread_ctx->ctx_state, p_thread_ctx);

	//Test
	//*(USHORT *)((PUCHAR)ethread + CTX_OFFSET) = 0xAAAA;
	//PVOID   objects[2] = { &p_thread_ctx->full_list.semaphore, &p_thread_ctx->exit_event };
	//while(1)
	//{
	//	////DbgPrint(" <Analysis> tid %d, out_buffer %x, base %08x\n", p_thread_ctx->tid, p_thread_ctx->out_buffer,
	//	////	    p_thread_ctx->out_buffer->base);
	//	ExInterlockedInsertTailList(&p_thread_ctx->free_list.listhead, &p_thread_ctx->out_buffer->entry,
	//		&p_thread_ctx->free_list.spinlock);
	//	KeReleaseSemaphore(&p_thread_ctx->free_list.semaphore, IO_NO_INCREMENT, 1, FALSE);

	//	KeWaitForMultipleObjects(2, objects, WaitAny, Executive, KernelMode, FALSE, NULL, NULL);
	//	if (p_thread_ctx->is_exit) 
	//	{
	//		break;
	//	}
	//	p_thread_ctx->out_buffer = (LIST_ELEMENT *)ExInterlockedRemoveHeadList(&p_thread_ctx->full_list.listhead,
	//		&p_thread_ctx->full_list.spinlock);
	//}
	//*(UCHAR *)((PUCHAR)ethread + CTX_OFFSET) = ANALYSIS_THREAD_CTX;


	DbgPrint(" <%d. Assisted thread exit.\n", p_thread_ctx->tid);
	
	if (p_thread_ctx->monitor_page_base)
	{
		for (ULONG i = 0; i < 2; i++)
		{
			ULONG  page = (ULONG)p_thread_ctx->monitor_page_base + i * PAGE_SIZE;
			if ((PVOID)page == p_thread_ctx->in_buffer->limit)
			{
				break;
			}
			PHYSICAL_ADDRESS  lpa = MmGetPhysicalAddress((PVOID)page);
			UpdateEptEntry(g_shared_data->ept_data_list[EPTP_MONITOR1], lpa.QuadPart, 3);
		}
	}
	for (ULONG i = 0; i < LOG_BLOCK_NUM; i++)
	{
		UpdateEptEntry(g_shared_data->ept_data_list[EPTP_MONITOR1], p_thread_ctx->guard_pa[i], 3);
	}
	KeIpiGenericCall(&IpiEptMonitorResetGuardPages, 0);

	ExFreePoolWithTag(p_thread_ctx->record_buffer, kHyperPlatformCommonPoolTag);
	ExFreePoolWithTag(p_thread_ctx, kHyperPlatformCommonPoolTag);

	KeUnstackDetachProcess(&kApc);

	InterlockedDecrement((LONG *)&g_athread_count);
	if (g_athread_count == 0)
	{
		KeSetEvent(&g_athread_event, IO_NO_INCREMENT, FALSE);
	}

	PsTerminateSystemThread(STATUS_SUCCESS);
}

ULONG __stdcall IntAnalysisThreadPageFaultHandler(ULONG faultAddr, KBITMAP_FAULT_FRAME *pFaultFrame)
{
	PVOID base = (PVOID)(faultAddr & 0xFFFFF000);
	ULONG pde = 0xc0600000 + (((ULONG)base >> 18) & 0x3ff8);
	ULONG pte = 0xc0000000 + (((ULONG)base >> 9) & 0x7ffff8);

	if ((faultAddr >= 0x80000000) || (pFaultFrame->Eip >= 0x80000000))
	{
		DbgPrint("[CHECK_FAULT_0] tid %d, fault %08x, eip %x\n", PsGetCurrentThreadId(), faultAddr, pFaultFrame->Eip);
		HYPERPLATFORM_COMMON_DBG_BREAK();
	}

	BUFFER_ENTRY *entry = (BUFFER_ENTRY *)g_entry_table[faultAddr >> 12];
	ULONG   pdpt_index = faultAddr >> 30;
	ULONG   pd_index = (faultAddr >> 21) & 0x1FF;
	ULONG   pt_index = (faultAddr >> 12) & 0x1FF;
	PVOID   pt_map_va = g_pt_map[pdpt_index][pd_index];

	*(ULONG *)((ULONG)pt_map_va + 8 * pt_index) |= 1; //p=1


	ProcessorData *processorData = processor_list[KeGetCurrentProcessorNumber()];

	processorData->counter_4++;

	//DbgPrint("[CHECK_FAULT] tid %d, fault %08x, eip %x, pte %x, map_entry %x, g_pt_map %x, index %x - %x - %x\n",
	//	PsGetCurrentThreadId(), faultAddr, pFaultFrame->Eip, pte, entry, g_pt_map, pdpt_index, pd_index, pt_index);

	//HYPERPLATFORM_COMMON_DBG_BREAK();

	//PVOID new_va = ExAllocatePoolWithTag(NonPagedPoolExecute, PAGE_SIZE,
	//	kHyperPlatformCommonPoolTag);
	//if (!new_va)
	//{
	//	DbgPrint("[CHECK] EmuAnalysisThreadPageFaultHandler alloc error.\n");
	//}
	//ULONG new_pa = *(ULONG *)(0xC0000000 + (((ULONG)new_va >> 9) & 0x7ffff8));
	//*(ULONG *)((ULONG)pt_map_va + 8 * pt_index) = new_pa;
	//BUFFER_ENTRY *node = (BUFFER_ENTRY *)g_entries_ptr;
	//node->Address = (PVOID)new_va;
	//node->MappedVa = (faultAddr & 0xFFFFF000) | 4;
	//g_entries_ptr = (PVOID)((ULONG)g_entries_ptr + sizeof(BUFFER_ENTRY));
	//InterlockedExchange((LONG *)&g_entry_table[faultAddr >> 12], (LONG)entry);

	//HANDLE  hFile;
	//IO_STATUS_BLOCK   IoStatusBlock;
	//NTSTATUS status = STATUS_SUCCESS;
	//OBJECT_ATTRIBUTES ObjectAttributes;
	//UNICODE_STRING FilePath;
	//WCHAR  wPath[64] = L"";

	//swprintf(wPath, L"\\??\\d:\\log\\s_page_%05x", (ULONG)faultAddr >> 12);
	//RtlInitUnicodeString(&FilePath, wPath);
	//InitializeObjectAttributes(&ObjectAttributes, &FilePath,
	//	OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	//status = ZwCreateFile(&hFile,
	//	GENERIC_WRITE, &ObjectAttributes, &IoStatusBlock, NULL,
	//	FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OVERWRITE_IF,
	//	FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0); //FILE_WRITE_THROUGH
	//if (!NT_SUCCESS(status))
	//{
	//	DbgPrint("[CHECK] Analysis fault, create file error - %#x\n", status);
	//	HYPERPLATFORM_COMMON_DBG_BREAK();
	//}
	//status = ZwReadFile(hFile, NULL, NULL, NULL, &IoStatusBlock, new_va, PAGE_SIZE, NULL, NULL);
	//if (!NT_SUCCESS(status))
	//{
	//	DbgPrint("[CHECK] Analysis fault, read file error - %x\n", status);
	//	HYPERPLATFORM_COMMON_DBG_BREAK();
	//}
	//ZwClose(hFile);

	return 0;
}

}