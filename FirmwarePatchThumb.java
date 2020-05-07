//TODO write a description for this script
//@author  pkiller
//@category _NEW_
//@keybinding
//@menupath
//@toolbar
//@ v0.1
/*
 fix notes:
   v0.1:  auto switch TMode
 */

import com.google.common.primitives.Bytes;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.address.*;

import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;


import ghidra.app.plugin.assembler.AssemblySyntaxException;
import ghidra.app.plugin.assembler.AssemblySemanticException;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.util.exception.CancelledException;

import java.io.*;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class FirmwarePatchThumb extends GhidraScript {

	final static String PATTERN_COMMENT = "^fileOffset=(\\d{1,}), length=(\\d{1,})$";
	final static String PATTERN_REGISTER = "^(r\\d{1,2}|pc|sp)$";
	final static String PATTERN_POINTER = "^\\[(r\\d{1,2}|pc|sp)\\]$";
	final static String PATTERN_POINTER_OFFSET = "^\\[(r\\d{1,2}|pc|sp),#(0x[0-9a-f]{1,8})\\]$";
	final static String PATTERN_IMM = "^#(0x[0-9a-f]{1,8})$";

	final static Address TEMP_ADDR = addr(0x300931ca);

	final static int ELEMENT_INVALID = -1;
	final static int ELEMENT_REGISTER = 0;
	final static int ELEMENT_POINTER = 1;
	final static int ELEMENT_POINTER_OFFSET = 2;
	final static int ELEMENT_IMM = 3;

	// parameters
	Address mPrintfFuncAddr;
	Address mJumpChunkAddr;
	Address mHookPointAddr;
	Address mTempBufferAddr;
	String mDataBufferAddrInstr;
	String mDataBufferSizeInstr;
	String mSourceBinPath; 
	String mPatchedBinPath;
	MemoryBlock[] mMemBlocks;


	public void run() throws Exception {
		//TODO Add User Code Here
		monitor.setMessage("Constructing Assember");

		// check blocks comment
		mMemBlocks = getMemoryBlocks();
		for (MemoryBlock memBlock : mMemBlocks) {
			if (!isValidComment(memBlock.getComment())) {
				popup(String.format("[ERR] The comment of memory block \"%s\" is an invalided.", memBlock.getName()));
				return;
			}
		}

		// ask parameters
		mTempBufferAddr = askAddress("Step: 1/8", "Temp Buffer Addr (Max 4Bytes):");
		mPrintfFuncAddr = askAddress("Step: 2/8", "Pritnf Function Address #prototype: int printf(const char*, ...) :");
		mJumpChunkAddr = askAddress("Step: 3/8", "Hook Code Address (output function + jump chunk):");
		mHookPointAddr = askAddress("Step: 4/8", "Hook Point Address:");

		do {
			mDataBufferAddrInstr = askString("Step: 5/8", "Data Buff Instr (store to 'r0', eg: mov r0,r5): ", "mov r0, r5");
			if (assembleInstrs(new String[]{mDataBufferAddrInstr}).length > 0) {
				break;
			}
			popup(String.format("[ERR] \"%S\" is an invalid instructions.", mDataBufferAddrInstr));
		} while(true);

		do {
			mDataBufferSizeInstr = askString("Step: 6/8", "Data Buff Size (store to 'r1', eg: mov r1,r6):", "mov r1, r1");
			if (assembleInstrs(new String[]{mDataBufferSizeInstr}).length > 0) {
				break;
			}
			popup(String.format("[ERR] \"%S\" is an invalid instructions.", mDataBufferSizeInstr));
		} while(true);
		mSourceBinPath = askString("Step: 7/8", "Source binary path (Template file):", mMemBlocks[0].getSourceName());
		mPatchedBinPath = askString("Step: 8/8", "Patched binary path (Output file):", mSourceBinPath + ".patched");
		// generateJumpChunk(mPrintfFuncAddr, 1);


		doIt();

	}

	void doIt() throws Exception {
		// hook point instr
		byte[] hookPointInstr = generateHookPoint();

		// bak hook point instr
		byte[] hookPointBackup = new byte[]{};
		Instruction instr = null;
		println("[Backup Hook Point]");
		do {
			if (instr == null) {
				instr = getInstructionAt(mHookPointAddr);
			} else {
				instr = instr.getNext();
			}
			hookPointBackup = Bytes.concat(hookPointBackup, instr.getBytes());
			println(String.format("  > %08x  %s", instr.getAddress().getOffset(), instr.toString()));
		} while(hookPointBackup.length < hookPointInstr.length);

		// jump chunk instr
		byte[] jumpChunkInstrs = generateJumpChunk(mJumpChunkAddr, hookPointBackup); // just get instrs size
		jumpChunkInstrs = generateJumpChunk(mJumpChunkAddr.add(jumpChunkInstrs.length), hookPointBackup);

		// output func instr
		byte[] outputFuncInstrs = generateOutputFunc();

		// write hook point instr
		FileWriter writer = new FileWriter(mSourceBinPath, mPatchedBinPath);
		long fileOffset = addr2Offset(mHookPointAddr);
		writer.write((int)fileOffset, hookPointInstr);
		println("[Patch Hook Point]");
		println(String.format("  > memory addr: 0x%08x", mHookPointAddr.getOffset()));
		println(String.format("  > file offset: 0x%x", fileOffset));
		println(String.format("  > HEX: %x, %x", hookPointInstr[0], hookPointInstr[1]));
		println("");

		// write jump chunk instr
		fileOffset = addr2Offset(mJumpChunkAddr);
		writer.write((int)fileOffset, jumpChunkInstrs);
		println("[Write Jump Chunk]");
		println(String.format("  > memory addr: 0x%08x", mJumpChunkAddr.getOffset()));
		println(String.format("  > file offset: 0x%x", fileOffset));
		println("");

		// write output function
		Address outputFuncAddr = mJumpChunkAddr.add(jumpChunkInstrs.length);
		fileOffset = addr2Offset(outputFuncAddr);
		writer.write((int)fileOffset, outputFuncInstrs);
		println("[Write Output Func]");
		println(String.format("  > memory addr: 0x%08x",  outputFuncAddr.getOffset()));
		println(String.format("  > file offset: 0x%x", fileOffset));
		println("");

		writer.save();

		println("[Pathed Successfully]");
		println("  > " + mPatchedBinPath);

	}

	long addr2Offset(Address addr) {
		mMemBlocks = getMemoryBlocks();
		for (MemoryBlock memBlock : mMemBlocks) {
			if (!memBlock.contains(addr)) {
				continue;
			}
			int[] area = getFileAreaOfMemBlockComment(memBlock.getComment());
			long offsetInBlock = addr.subtract(memBlock.getStart());
			addr.
			return area[0] + offsetInBlock;
		}
		return -1;
	}

	boolean isValidComment(String comment) {
		return Pattern.matches(PATTERN_COMMENT, comment);
	}

	// {fileOffset, length}
	int[] getFileAreaOfMemBlockComment(String comment) {
		int area[] = {0,0};
		Pattern r = Pattern.compile(PATTERN_COMMENT);
		Matcher m = r.matcher(comment);
		if (m.find()) {
			area[0] = Integer.valueOf(m.group(1));
			area[1] = Integer.valueOf(m.group(2));
			return area;
		} else {
			return null;
		}
	}

	static int getElementType(String buffSize) {
		buffSize = buffSize.toLowerCase().
				replace(" ", "");
		if (Pattern.matches(PATTERN_REGISTER, buffSize)) {
			return ELEMENT_REGISTER;
		} else if (Pattern.matches(PATTERN_IMM, buffSize)) {
			return ELEMENT_IMM;
		} else if (Pattern.matches(PATTERN_POINTER, buffSize)) {
			return ELEMENT_POINTER;
		} else if (Pattern.matches(PATTERN_POINTER_OFFSET, buffSize)) {
			return ELEMENT_POINTER;
		}
		return ELEMENT_INVALID;
	}

	static long thumbAddr(long addr) {
		if (addr%2 == 0) {
			return addr + 1;
		}
		return addr;
	}

	static Address addr(long addr) {
		return Address.NO_ADDRESS.addWrap(addr);
	}

	static String[] generateMovInstrs(String dstRegister, String srcElement) {
		String tmpSrcElement = srcElement.toLowerCase()
				.replace(" ", "");
		if (ELEMENT_REGISTER == getElementType(tmpSrcElement)) {
			String register = tmpSrcElement;
			return new String[] {
					String.format("mov  %s, %s", dstRegister, register),
					"nop"
			};
		} else if (ELEMENT_IMM == getElementType(tmpSrcElement)) {
			String hex = tmpSrcElement
					.replace("0x", "")
					.replace("#", "");
			int size = Integer.parseInt(hex, 16);

			return new String [] {
					String.format("movw  %s, #0x%x", dstRegister, (size & 0x0000FFFF)),
					String.format("movt  %s, #0x%x", dstRegister, (size & 0xFFFF0000) >>> 16),
			};
		} else if (ELEMENT_POINTER == getElementType(tmpSrcElement)) {
			String pointer = tmpSrcElement;
			return new String[] {
					String.format("ldr.w  %s, %s", dstRegister, pointer),
					"nop"
			};
		} else if (ELEMENT_POINTER_OFFSET == getElementType(tmpSrcElement)) {
			String pointer = tmpSrcElement;
			return new String[] {
					String.format("ldr.w  %s, %s", dstRegister, pointer),
					"nop"
			};
		}
		return new String[] {};
	}

	byte[] assembleInstrs(String[] instrs) {
		Assembler asm = Assemblers.getAssembler(currentProgram);
		List<Byte> blockByteList = new ArrayList<>();
		for (String instrLine : instrs) {

			try {
				clearListing(mTempBufferAddr, mTempBufferAddr.add(3));

				Register tmodeReg = currentProgram.getProgramContext().getRegister("TMode");
				currentProgram.getProgramContext().setRegisterValue(mTempBufferAddr, mTempBufferAddr.add(3), new RegisterValue(tmodeReg, BigInteger.ONE));

				println("assemble instr: " + instrLine);
				InstructionBlock block = asm.assemble(mTempBufferAddr, instrLine);
				// println(String.format("start: %x  end:%x", block.getStartAddress().getOffset(), block.getMaxAddress().getOffset()));
				byte[] instr = block.getInstructionAt(block.getStartAddress()).getBytes();
				for (byte b : instr) {
					blockByteList.add(b);
				}
			} catch (AssemblySyntaxException e) {
				e.printStackTrace();
				println("[ERR] assembleInstrs() failed: " + e.toString());
				return null;
			} catch (AssemblySemanticException e) {
				e.printStackTrace();
				println("[ERR] assembleInstrs() failed: " + e.toString());
				return null;
			} catch (MemoryAccessException e) {
				e.printStackTrace();
				println("[ERR] assembleInstrs() failed: " + e.toString());
				return null;
			} catch (AddressOverflowException e) {
				e.printStackTrace();
				println("[ERR] assembleInstrs() failed: " + e.toString());
				return null;
			} catch (CancelledException e) {
				e.printStackTrace();
			} catch (ContextChangeException e) {
				e.printStackTrace();
			}

		}
		return Bytes.toArray(blockByteList);
	}

	byte[] generateJumpChunk(Address outputFuncAddr, byte[] hookPointBakupInstrs) {
        /*
                    ; HalJTAGPinCtrlRtl8195A(0, 1);
                    "movw       r4,#0x280d",
                    "movt       r4,#0x0",
                    "mov        r0,#0x0",
                    "mvn        r1,#0x0",
                    "blx        r4",
         */
		// println(String.format("outputFuncAddr: %x, %x",  outputFuncAddr.getOffset(), hookPointBakupInstrs.length));
		long lOutpoutFuncAddr = thumbAddr(outputFuncAddr.getOffset());
		long lResumeAddr = thumbAddr(mHookPointAddr.getOffset()) + hookPointBakupInstrs.length;
        String[] blockInstrs = new String[]{
					"mov    r12,lr",
					"push   {r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, sp}",
					"add sp, #0x38",
					mDataBufferAddrInstr,				// r0, dataBuff
					mDataBufferSizeInstr,				// r1, dataSize
				    "sub sp, #0x38",
    String.format("movw   r4,#0x%x", (lOutpoutFuncAddr & 0x0000FFFF)),	// output func addr
    String.format("movt   r4,#0x%x", (lOutpoutFuncAddr & 0xFFFF0000) >>> 16 ),
					"blx   r4",  					// call output func
					"nop",
					"nop",
					"pop   {r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, sp}",
					"mov   lr,r12"};


        String[] resumeInstrs = new String[] {
    String.format("movw   r12,#0x%x", lResumeAddr & 0x0000FFFF),  // resume flow
	String.format("movt   r12,#0x%x", (lResumeAddr & 0xFFFF0000) >>> 16),
				"bx   r12"
		};

        byte[] resultInstrs = Bytes.concat(assembleInstrs(blockInstrs), hookPointBakupInstrs);
		resultInstrs = Bytes.concat(resultInstrs, assembleInstrs(resumeInstrs));
		return resultInstrs;
	}

	byte[] generateOutputFunc() {
		byte[] outputFuncBytes = hexToByte("80 b5 88 b0 00 af 78 60 39 60 00 23 fb 60 43 f6 57 78 c3 f2 00 08 7e" +
				" 46 64 36 00 bf 30 1c c0 47 00 23 fb 60 0a e0 fa 68 79 68 0a 44 12 78 30 1c 08 30 11 46 c0 47 fb" +
				" 68 01 33 fb 60 fa 68 3b 68 9a 42 f0 db 30 1c 10 30 c0 47 00 23 fb 60 0a e0 fa 68 79 68 0a 44 12" +
				" 78 30 1c 1c 30 11 46 c0 47 fb 68 01 33 fb 60 fa 68 3b 68 9a 42 f0 db 30 1c 20 30 c0 47 20 37 bd" +
				" 46 80 bd 00 00 00 00 0a 0a 48 45 58 3a 20 00 25 30 32 58 20 00 00 00 0a 0a 53 74 72 69 6e 67 3a" +
				" 20 00 00 25 63 00 00 0a 0a 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 65 6e 64 3d 3d 3d 3d 3d 3d 3d" +
				" 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 0a 00 ");

		/*
                              **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             void __stdcall output_bytes(void * param_1, int param_2)
                               assume LRset = 0x0
                               assume TMode = 0x1
             void              <VOID>         <RETURN>
             void *            r0:4           param_1
             int               r1:4           param_2
             undefined4        Stack[-0x1c]:4 local_1c
             undefined4        Stack[-0x24]:4 local_24
             undefined4        Stack[-0x28]:4 local_28
                             output_bytes                                    XREF[1]:     3005253a(c)
        30052400 80 b5           push       { r7, lr }
        30052402 88 b0           sub        sp,#0x20
        30052404 00 af           add        r7,sp,#0x0
        30052406 78 60           str        param_1,[r7,#0x4]
        30052408 39 60           str        param_2,[r7,#0x0]
        3005240a 00 23           mov        r3,#0x0
        3005240c fb 60           str        r3,[r7,#0xc]
        3005240e 43 f6 57 78     movw       r8,#0x3f57
        30052412 c3 f2 00 08     movt       r8,#0x3000
        30052416 7e 46           mov        r6,pc
        30052418 64 36           add        r6,#0x64
        3005241a 00 bf           nop
        3005241c 30 1c           mov        param_1=>DAT_300524c0,r6                         = 3Dh    =
        3005241e c0 47           blx        r8=>UART_Print                                   undefined8 UART_Print(char * par
        30052420 00 23           mov        r3,#0x0
        30052422 fb 60           str        r3,[r7,#0xc]
        30052424 0a e0           b          LAB_3005243c
                             LAB_30052426                                    XREF[1]:     30052442(j)
        30052426 fa 68           ldr        r2,[r7,#0xc]
        30052428 79 68           ldr        param_2,[r7,#0x4]
        3005242a 0a 44           add        r2,param_2
        3005242c 12 78           ldrb       r2,[r2,#0x0]
        3005242e 30 1c           mov        param_1,r6
        30052430 08 30           add        param_1,#0x8
        30052432 11 46           mov        param_2,r2
        30052434 c0 47           blx        r8
        30052436 fb 68           ldr        r3,[r7,#0xc]
        30052438 01 33           add        r3,#0x1
        3005243a fb 60           str        r3,[r7,#0xc]
                             LAB_3005243c                                    XREF[1]:     30052424(j)
        3005243c fa 68           ldr        r2,[r7,#0xc]
        3005243e 3b 68           ldr        r3,[r7,#0x0]
        30052440 9a 42           cmp        r2,r3
        30052442 f0 db           blt        LAB_30052426
        30052444 30 1c           mov        param_1,r6
        30052446 10 30           add        param_1,#0x10
        30052448 c0 47           blx        r8
        3005244a 00 23           mov        r3,#0x0
        3005244c fb 60           str        r3,[r7,#0xc]
        3005244e 0a e0           b          LAB_30052466
                             LAB_30052450                                    XREF[1]:     3005246c(j)
        30052450 fa 68           ldr        r2,[r7,#0xc]
        30052452 79 68           ldr        param_2,[r7,#0x4]
        30052454 0a 44           add        r2,param_2
        30052456 12 78           ldrb       r2,[r2,#0x0]
        30052458 30 1c           mov        param_1,r6
        3005245a 1c 30           add        param_1,#0x1c
        3005245c 11 46           mov        param_2,r2
        3005245e c0 47           blx        r8
        30052460 fb 68           ldr        r3,[r7,#0xc]
        30052462 01 33           add        r3,#0x1
        30052464 fb 60           str        r3,[r7,#0xc]
                             LAB_30052466                                    XREF[1]:     3005244e(j)
        30052466 fa 68           ldr        r2,[r7,#0xc]
        30052468 3b 68           ldr        r3,[r7,#0x0]
        3005246a 9a 42           cmp        r2,r3
        3005246c f0 db           blt        LAB_30052450
        3005246e 30 1c           mov        param_1,r6
        30052470 20 30           add        param_1,#0x20
        30052472 c0 47           blx        r8
        30052474 20 37           add        r7,#0x20
        30052476 bd 46           mov        sp,r7
        30052478 80 bd           pop        { r7, pc }
        3005247a 00              ??         00h
        3005247b 00              ??         00h
        3005247c 00              ??         00h
        3005247d 00              ??         00h
        3005247e 0a              ??         0Ah
        3005247f 0a              ??         0Ah
        30052480 48              ??         48h    H
        30052481 45              ??         45h    E
        30052482 58              ??         58h    X
        30052483 3a              ??         3Ah    :
        30052484 20              ??         20h
        30052485 00              ??         00h
        30052486 25              ??         25h    %
        30052487 30              ??         30h    0
        30052488 32              ??         32h    2
        30052489 58              ??         58h    X
        3005248a 20              ??         20h
        3005248b 00              ??         00h
        3005248c 00              ??         00h
        3005248d 00              ??         00h
        3005248e 0a              ??         0Ah
        3005248f 0a              ??         0Ah
        30052490 53              ??         53h    S
        30052491 74              ??         74h    t
        30052492 72              ??         72h    r
        30052493 69              ??         69h    i
        30052494 6e              ??         6Eh    n
        30052495 67              ??         67h    g
        30052496 3a              ??         3Ah    :
        30052497 20              ??         20h
        30052498 00              ??         00h
        30052499 00              ??         00h
        3005249a 25              ??         25h    %
        3005249b 63              ??         63h    c
        3005249c 00              ??         00h
        3005249d 00              ??         00h
        3005249e 0a              ??         0Ah
        3005249f 0a              ??         0Ah
        300524a0 3d              ??         3Dh    =
        300524a1 3d              ??         3Dh    =
        300524a2 3d              ??         3Dh    =
        300524a3 3d              ??         3Dh    =
        300524a4 3d              ??         3Dh    =
        300524a5 3d              ??         3Dh    =
        300524a6 3d              ??         3Dh    =
        300524a7 3d              ??         3Dh    =
        300524a8 3d              ??         3Dh    =
        300524a9 3d              ??         3Dh    =
        300524aa 3d              ??         3Dh    =
        300524ab 3d              ??         3Dh    =
        300524ac 3d              ??         3Dh    =
        300524ad 65              ??         65h    e
        300524ae 6e              ??         6Eh    n
        300524af 64              ??         64h    d
        300524b0 3d              ??         3Dh    =
        300524b1 3d              ??         3Dh    =
        300524b2 3d              ??         3Dh    =
        300524b3 3d              ??         3Dh    =
        300524b4 3d              ??         3Dh    =
        300524b5 3d              ??         3Dh    =
        300524b6 3d              ??         3Dh    =
        300524b7 3d              ??         3Dh    =
        300524b8 3d              ??         3Dh    =
        300524b9 3d              ??         3Dh    =
        300524ba 3d              ??         3Dh    =
        300524bb 3d              ??         3Dh    =
        300524bc 3d              ??         3Dh    =
        300524bd 3d              ??         3Dh    =
        300524be 3d              ??         3Dh    =
        300524bf 3d              ??         3Dh    =
                             DAT_300524c0                                    XREF[1]:     output_bytes:3005241c(*)
        300524c0 3d              ??         3Dh    =
        300524c1 0a              ??         0Ah
        300524c2 00              ??         00h
		 */

		long lPrintfFuncAddr = thumbAddr(mPrintfFuncAddr.getOffset());

		String[] patchPrintfFuncAddrInstrs = new String[]{
				String.format("movw r8, #0x%x", lPrintfFuncAddr & 0x0000FFFF),
				String.format("movt r8, #0x%x", (lPrintfFuncAddr & 0xFFFF0000) >>> 16),
		};

		byte[] patchInstrs = assembleInstrs(patchPrintfFuncAddrInstrs);
		// println(String.format("01: %x, 02: %x.", outputFuncBytes[0], outputFuncBytes[1]));
		System.arraycopy(patchInstrs, 0, outputFuncBytes, 14, patchInstrs.length);
		// println(String.format("01: %x, 02: %x.", outputFuncBytes[0], outputFuncBytes[1]));
		return outputFuncBytes;
	}

	byte[] generateHookPoint() {
		long lJumpChunkAddr = thumbAddr(mJumpChunkAddr.getOffset());
		String[] hookPointInstrs = new String[]{
				String.format("movw r8, #0x%x", (lJumpChunkAddr & 0x0000FFFF)),
				String.format("movt r8, #0x%x", (lJumpChunkAddr & 0xFFFF0000) >>> 16),
				"bx r8"
		};

		return assembleInstrs(hookPointInstrs);
	}

	static byte[] hexToByte(String hex){
		hex = hex.replace(" ", "");
		int m = 0, n = 0;
		int byteLen = hex.length() / 2;
		byte[] ret = new byte[byteLen];
		for (int i = 0; i < byteLen; i++) {
			m = i * 2 + 1;
			n = m + 1;
			int intVal = Integer.decode("0x" + hex.substring(i * 2, m) + hex.substring(m, n));
			ret[i] = Byte.valueOf((byte)intVal);
		}
		return ret;
	}

	class FileWriter{
		byte[] mData = null;
		String mDstPath = null;

		 public FileWriter(String srcPath, String dstPath) {
			mData = readFile(srcPath);
			mDstPath = dstPath;
		}

		void write(int dstOffset, byte[] data) {
			write(dstOffset, data, 0, data.length);
		}

		void write(int dstOffset, byte[] data, int dataOffset, int dataLen) {
			System.arraycopy(data, dataOffset, mData, dstOffset, dataLen);
		}

		void save() {
			if (mData == null) {
				return;
			}
			writeFile(mDstPath, mData);
		}

		void close() {
			mData = null;
			mDstPath = null;
		}

		boolean writeFile(String fileName, byte[] data) {
			try {
				File file = new File(fileName);
				FileOutputStream fileOutputStream = new FileOutputStream(file);
				fileOutputStream.write(data);
				fileOutputStream.close();
				return true;
			} catch (Exception e) {
				e.printStackTrace();
				return false;
			}
		}

		byte[] readFile(String fileName) {
			try {
				File file = new File(fileName);
				byte[] data = new byte[(int)file.length()];
				FileInputStream fileIntputStream = new FileInputStream(file);
				fileIntputStream.read(data, 0, data.length);
				fileIntputStream.close();
				return data;
			} catch (Exception e) {
				e.printStackTrace();
				return null;
			}
		}
	}
}
