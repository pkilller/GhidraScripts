//TODO write a description for this script
//@author  pkiller
//@category _NEW_
//@keybinding
//@menupath
//@toolbar

import com.google.common.primitives.Bytes;
import ghidra.app.script.GhidraScript;
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

import java.io.*;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class FirmwarePatchThumb extends GhidraScript {

	final static String PATTERN_COMMENT = "^fileOffset=(\\d{1,}), length=(\\d{1,})$";
	final static String PATTERN_REGISTER = "^(r\\d{1,2}|pc|sp)$";
	final static String PATTERN_HEX_INTEGER = "^(0x[0-9a-f]{1,8})$";
	final static Address TEMP_ADDR = addr(0x300931ca);

	final static int ELEMENT_INVALID = -1;
	final static int ELEMENT_REGISTER = 0;
	final static int ELEMENT_HEX_INTEGER = 1;

	// parameters
	Address mPrintfFuncAddr;
	Address mJumpChunkAddr;
	Address mHookPointAddr;
	Address mTempBufferAddr;
	String mDataBufferReg;
	String mDatabuffSize;
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
		mDataBufferReg = askString("Step: 5/8", "Data Buffer Register (eg. r0):", "r0");
		do {
			mDatabuffSize = askString("Step: 6/8", "Bufer Size (eg. r1  or  #0x10):", "#0x10");
			if (getElementType(mDatabuffSize) != ELEMENT_INVALID) {
				break;
			}
			popup(String.format("[ERR] \"%S\" is an invalid element and must be a register or immediate number.\n(eg. r1 or #0x10)", mDatabuffSize));
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
			println(String.format("  > %x08  %s", instr.getAddress().getOffset(), instr.toString()));
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
		buffSize = buffSize.toLowerCase().replace("#", "");
		if (Pattern.matches(PATTERN_REGISTER, buffSize)) {
			return ELEMENT_REGISTER;
		} else if (Pattern.matches(PATTERN_HEX_INTEGER, buffSize)) {
			return ELEMENT_HEX_INTEGER;
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

	static String[] generateMovBuffSize(String dataSizeElement) {
		String buffSize = dataSizeElement.toLowerCase().replace("#", "");
		if (ELEMENT_REGISTER == getElementType(buffSize)) {
			String register = buffSize;
			return new String[] {
					String.format("mov  r1, %s", register),
					"nop"
			};
		} else if (ELEMENT_HEX_INTEGER == getElementType(buffSize)) {
			String hex = buffSize.replace("0x", "");
			int size = Integer.parseInt(hex, 16);

			return new String [] {
					String.format("movw  r1, #0x%x", (size & 0x0000FFFF)),
					String.format("movt  r1, #0x%x", (size & 0xFFFF0000) >>> 16),
			};
		}
		return new String[] {};
	}

	byte[] assembleInstrs(String[] instrs) {
		Assembler asm = Assemblers.getAssembler(currentProgram);
		List<Byte> blockByteList = new ArrayList<>();
		for (String instrLine : instrs) {

			try {
				InstructionBlock block = asm.assemble(mTempBufferAddr, instrLine);
				// println(String.format("start: %x  end:%x", block.getStartAddress().getOffset(), block.getMaxAddress().getOffset()));
				byte[] instr = block.getInstructionAt(block.getStartAddress()).getBytes();
				for (byte b : instr) {
					blockByteList.add(b);
					// println(String.format("instr: %x", b));
				}
			} catch (AssemblySyntaxException e) {
				e.printStackTrace();
			} catch (AssemblySemanticException e) {
				e.printStackTrace();
			} catch (MemoryAccessException e) {
				e.printStackTrace();
			} catch (AddressOverflowException e) {
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
		String[] movBuffSizeInstrs = generateMovBuffSize(mDatabuffSize);
		long lOutpoutFuncAddr = thumbAddr(outputFuncAddr.getOffset());
		long lResumeAddr = thumbAddr(mHookPointAddr.getOffset()) + hookPointBakupInstrs.length;

        String[] blockInstrs = new String[]{
					"mov    r10,lr",
					"push   {r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, sp}",
					"nop",
	String.format("mov  r0,%s", mDataBufferReg),	// r0, dataBuff
					movBuffSizeInstrs[0],				// r1, dataSize
					movBuffSizeInstrs[1],
    String.format("movw   r4,#0x%x", (lOutpoutFuncAddr & 0x0000FFFF)),	// output func addr
    String.format("movt   r4,#0x%x", (lOutpoutFuncAddr & 0xFFFF0000) >>> 16 ),
					"blx   r4",  					// call output func
					"nop",
					"nop",
					"pop   {r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, sp}",
					"mov   lr,r10"};


        String[] resumeInstrs = new String[] {
    String.format("movw   r10,#0x%x", lResumeAddr & 0x0000FFFF),  // resume flow
	String.format("movt   r10,#0x%x", (lResumeAddr & 0xFFFF0000) >>> 16),
				"bx   r10"
		};

        byte[] resultInstrs = Bytes.concat(assembleInstrs(blockInstrs), hookPointBakupInstrs);
		resultInstrs = Bytes.concat(resultInstrs, assembleInstrs(resumeInstrs));
		return resultInstrs;
	}

	byte[] generateOutputFunc() {
		byte[] outputFuncBytes = hexToByte("80 b5 88 b0 00 af 78 60 39 60 00 23 fb 60 43 f6 57 78 c3 f2 00 08 7e 46 a0 36 " +
				"06 36 00 bf 30 1c c0 47 00 23 fb 60 11 e0 00 bf 00 bf 00 bf 00 bf 00 bf fa 68 79 68 0a 44 12 78 " +
				"00 bf 30 1c 08 30 00 bf 11 46 c0 47 fb 68 01 33 fb 60 fa 68 3b 68 9a 42 e9 db 00 bf 00 bf 00 bf " +
				"00 bf 00 bf 30 1c 10 30 00 bf 00 bf c0 47 00 23 fb 60 11 e0 00 bf 00 bf 00 bf 00 bf 00 bf fa 68 " +
				"79 68 0a 44 12 78 00 bf 30 1c 1c 30 00 bf 11 46 c0 47 fb 68 01 33 fb 60 fa 68 3b 68 9a 42 e9 db " +
				"00 bf 00 bf 00 bf 00 bf 00 bf 30 1c 20 30 00 bf 00 bf c0 47 20 37 bd 46 80 bd 00 00 00 00 30 31 " +
				"02 03 04 00 00 00 0a 0a 48 45 58 3a 20 00 25 30 32 58 20 00 00 00 0a 0a 53 74 72 69 6e 67 3a 20 " +
				"00 00 25 63 00 00 0a 0a 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 65 6e 64 3d 3d 3d 3d 3d 3d 3d 3d " +
				"3d 3d 3d 3d 3d 3d 3d 3d 3d 0a 00");

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
             undefined4        Stack[-0x1c]:4 local_1c                                XREF[11]:    3005240c(W),
                                                                                                   30052424(W),
                                                                                                   30052432(R),
                                                                                                   30052446(R),
                                                                                                   3005244a(W),
                                                                                                   3005244c(R),
                                                                                                   3005246a(W),
                                                                                                   30052478(R),
                                                                                                   3005248c(R),
                                                                                                   30052490(W),
                                                                                                   30052492(R)
             undefined4        Stack[-0x24]:4 local_24                                XREF[3]:     30052406(W),
                                                                                                   30052434(R),
                                                                                                   3005247a(R)
             undefined4        Stack[-0x28]:4 local_28                                XREF[3]:     30052408(W),
                                                                                                   3005244e(R),
                                                                                                   30052494(R)
                             output_bytes                                    XREF[1]:     3005253a(c)
        30052400 80 b5           push       { r7, lr }
        30052402 88 b0           sub        sp,#0x20
        30052404 00 af           add        r7,sp,#0x0
        30052406 78 60           str        param_1,[r7,#local_24]
        30052408 39 60           str        param_2,[r7,#0x0]=>local_28
        3005240a 00 23           mov        r3,#0x0
        3005240c fb 60           str        r3,[r7,#local_1c]
        3005240e 43 f6 57 78     movw       r8,#0x3f57        		// will patch
        30052412 c3 f2 00 08     movt       r8,#0x3000        		// will patch
        30052416 7e 46           mov        r6,pc
        30052418 a0 36           add        r6,#0xa0
        3005241a 06 36           add        r6,#0x6
        3005241c 00 bf           nop
        3005241e 30 1c           mov        param_1,r6
        30052420 c0 47           blx        r8
        30052422 00 23           mov        r3,#0x0
        30052424 fb 60           str        r3,[r7,#local_1c]
        30052426 11 e0           b          LAB_3005244c
                             LAB_30052428                                    XREF[1]:     30052452(j)
        30052428 00 bf           nop
        3005242a 00 bf           nop
        3005242c 00 bf           nop
        3005242e 00 bf           nop
        30052430 00 bf           nop
        30052432 fa 68           ldr        r2,[r7,#local_1c]
        30052434 79 68           ldr        param_2,[r7,#local_24]
        30052436 0a 44           add        r2,param_2
        30052438 12 78           ldrb       r2,[r2,#0x0]
        3005243a 00 bf           nop
        3005243c 30 1c           mov        param_1,r6
        3005243e 08 30           add        param_1,#0x8
        30052440 00 bf           nop
        30052442 11 46           mov        param_2,r2
        30052444 c0 47           blx        r8
        30052446 fb 68           ldr        r3,[r7,#local_1c]
        30052448 01 33           add        r3,#0x1
        3005244a fb 60           str        r3,[r7,#local_1c]
                             LAB_3005244c                                    XREF[1]:     30052426(j)
        3005244c fa 68           ldr        r2,[r7,#local_1c]
        3005244e 3b 68           ldr        r3,[r7,#0x0]=>local_28
        30052450 9a 42           cmp        r2,r3
        30052452 e9 db           blt        LAB_30052428
        30052454 00 bf           nop
        30052456 00 bf           nop
        30052458 00 bf           nop
        3005245a 00 bf           nop
        3005245c 00 bf           nop
        3005245e 30 1c           mov        param_1,r6
        30052460 10 30           add        param_1,#0x10
        30052462 00 bf           nop
        30052464 00 bf           nop
        30052466 c0 47           blx        r8
        30052468 00 23           mov        r3,#0x0
        3005246a fb 60           str        r3,[r7,#local_1c]
        3005246c 11 e0           b          LAB_30052492
                             LAB_3005246e                                    XREF[1]:     30052498(j)
        3005246e 00 bf           nop
        30052470 00 bf           nop
        30052472 00 bf           nop
        30052474 00 bf           nop
        30052476 00 bf           nop
        30052478 fa 68           ldr        r2,[r7,#local_1c]
        3005247a 79 68           ldr        param_2,[r7,#local_24]
        3005247c 0a 44           add        r2,param_2
        3005247e 12 78           ldrb       r2,[r2,#0x0]
        30052480 00 bf           nop
        30052482 30 1c           mov        param_1,r6
        30052484 1c 30           add        param_1,#0x1c
        30052486 00 bf           nop
        30052488 11 46           mov        param_2,r2
        3005248a c0 47           blx        r8
        3005248c fb 68           ldr        r3,[r7,#local_1c]
        3005248e 01 33           add        r3,#0x1
        30052490 fb 60           str        r3,[r7,#local_1c]
                             LAB_30052492                                    XREF[1]:     3005246c(j)
        30052492 fa 68           ldr        r2,[r7,#local_1c]
        30052494 3b 68           ldr        r3,[r7,#0x0]=>local_28
        30052496 9a 42           cmp        r2,r3
        30052498 e9 db           blt        LAB_3005246e
        3005249a 00 bf           nop
        3005249c 00 bf           nop
        3005249e 00 bf           nop
        300524a0 00 bf           nop
        300524a2 00 bf           nop
        300524a4 30 1c           mov        param_1,r6
        300524a6 20 30           add        param_1,#0x20
        300524a8 00 bf           nop
        300524aa 00 bf           nop
        300524ac c0 47           blx        r8
        300524ae 20 37           add        r7,#0x20
        300524b0 bd 46           mov        sp,r7
        300524b2 80 bd           pop        { r7, pc }
        300524b4 00              ??         00h
        300524b5 00              ??         00h
        300524b6 00              ??         00h
        300524b7 00              ??         00h
        300524b8 30              ??         30h    0
        300524b9 31              ??         31h    1
        300524ba 02              ??         02h
        300524bb 03              ??         03h
        300524bc 04              ??         04h
        300524bd 00              ??         00h
        300524be 00              ??         00h
        300524bf 00              ??         00h
        300524c0 0a 0a 48        ds         "\n\nHEX: "
                 45 58 3a
                 20 00
        300524c8 25 30 32        ds         "%02X "
                 58 20 00
        300524ce 00              ??         00h
        300524cf 00              ??         00h
        300524d0 0a 0a 53        ds         "\n\nString: "
                 74 72 69
                 6e 67 3a
        300524db 00              ??         00h
        300524dc 25 63 00        ds         "%c"
        300524df 00              ??         00h
        300524e0 0a 0a 3d        ds         "\n\n=============end=================\n"
                 3d 3d 3d
                 3d 3d 3d

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
		int byteLen = hex.length() / 2; // 每两个字符描述一个字节
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
