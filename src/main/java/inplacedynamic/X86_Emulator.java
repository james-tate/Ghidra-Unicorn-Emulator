package inplacedynamic;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

import ghidra.program.flatapi.FlatProgramAPI;
import unicorn.*;

public class X86_Emulator {
	
	private static X86_Emulator_Provider provider;
	public static long ADDRESS;
	public static long END;
	public static long BASE = 0x10000;
	public static long BASE_MEMORY_SIZE = 2 * 1024 * 1024;
	public static long STACK = 0x0000;
	public static long WORKING = 0x50000;
	public static long STACK_SIZE = 2*1024;
	private static FlatProgramAPI API;
	public static byte[] X86_CODE;
	private static int status;
	private static Unicorn u;
	public static Long rax;
	public static Long rbx;
	public static Long rcx;
	public static Long rdx;
	public static Long rsi;
	public static Long rdi;
	public static Long r8;
	public static Long r9;
	public static Long r10;
	public static Long r11;
	public static Long r12;
	public static Long r13;
	public static Long r14;
	public static Long r15;
	public static Long rsp;
	public static Long rbp;
	public static Long rip;
	
	public X86_Emulator(X86_Emulator_Provider pr, long address, byte[] code, FlatProgramAPI api){
		X86_CODE = code;
		provider = pr;
		ADDRESS = address;
		API = api;
		BASE = provider.getBase();
		BASE_MEMORY_SIZE = provider.getBaseLen();
		END = ADDRESS + X86_CODE.length;
		STACK = BASE + BASE_MEMORY_SIZE;

		// add function number or name
		provider.addText(String.format("Emulate X64 code at function 0x%x with end 0x%x\n", ADDRESS, END));

		// Initialize emulator in ARM mode
		u = new Unicorn(UnicornConst.UC_ARCH_X86, UnicornConst.UC_MODE_64);

		// map 2MB memory for this emulation
		u.mem_map(BASE, BASE_MEMORY_SIZE, UnicornConst.UC_PROT_ALL);
		// stack

		// write machine code to be emulated to memory
		u.mem_write(ADDRESS, X86_CODE);

		provider.UC_X86_REG_RSP.setText(String.format("0x%x", STACK));
		//		byte [] mem = u.mem_read(ADDRESS, X86_CODE.length);
		//		System.out.println(mem);
		//		for(byte b: mem)
		//			provider.addText(String.format("0x%x", b));


		// initialize machine registers
		// u.reg_write(X86Const.UC_X86_REG_RAX, (Long.parseLong(provider.UC_X86_REG_RAX.getText().substring(2), 16)));
		// u.reg_write(X86Const.UC_X86_REG_RBX, (Long.parseLong(provider.UC_X86_REG_RBX.getText().substring(2), 16)));
		// u.reg_write(X86Const.UC_X86_REG_RCX, (Long.parseLong(provider.UC_X86_REG_RCX.getText().substring(2), 16)));
		// u.reg_write(X86Const.UC_X86_REG_RDX, (Long.parseLong(provider.UC_X86_REG_RDX.getText().substring(2), 16)));
		// u.reg_write(X86Const.UC_X86_REG_RSI, (Long.parseLong(provider.UC_X86_REG_RSI.getText().substring(2), 16)));
		// u.reg_write(X86Const.UC_X86_REG_RDI, (Long.parseLong(provider.UC_X86_REG_RDI.getText().substring(2), 16)));
		// u.reg_write(X86Const.UC_X86_REG_R8, (Long.parseLong(provider.labelR8.getText().substring(2), 16)));
		// u.reg_write(X86Const.UC_X86_REG_R9, (Long.parseLong(provider.labelR9.getText().substring(2), 16)));
		// u.reg_write(X86Const.UC_X86_REG_R10, (Long.parseLong(provider.labelR10.getText().substring(2), 16)));
		// u.reg_write(X86Const.UC_X86_REG_R11, (Long.parseLong(provider.labelR11.getText().substring(2), 16)));
		// u.reg_write(X86Const.UC_X86_REG_R12, (Long.parseLong(provider.labelR12.getText().substring(2), 16)));
		// u.reg_write(X86Const.UC_X86_REG_R13, (Long.parseLong(provider.labelR13.getText().substring(2), 16)));
		// u.reg_write(X86Const.UC_X86_REG_R14, (Long.parseLong(provider.labelR14.getText().substring(2), 16)));
		// u.reg_write(X86Const.UC_X86_REG_R15, ((Long.parseLong(provider.labelR15.getText().substring(2), 16))));
		u.reg_write(X86Const.UC_X86_REG_RSP, ((Long.parseLong(provider.UC_X86_REG_RSP.getText().substring(2), 16))));
		//u.reg_write(X86Const.UC_X86_REG_RBP, ((Long.parseLong(provider.UC_X86_REG_RBP.getText().substring(2), 16))));
		u.reg_write(X86Const.UC_X86_REG_RIP, ADDRESS);

		rip = (Long)u.reg_read(X86Const.UC_X86_REG_RIP);
		provider.UC_X86_REG_RIP.setText(String.format("0x%x", rip.intValue()));

		// tracing all basic blocks with customized callback
		u.hook_add(new MyBlockHook(), 1, 0, null);

		// tracing one instruction at ADDRESS with customized callback
		u.hook_add(new MyCodeHook(), ADDRESS, ADDRESS, null);

		u.hook_add(new MyWrite64Hook(), 1, 0, null);
   
       	// tracing all memory READ access (with @begin > @end)
       	u.hook_add(new MyRead64Hook(), 1, 0, null);

		status = 1;}

		public void getRegs() {
			rax = (Long)u.reg_read(X86Const.UC_X86_REG_RAX);
			rbx = (Long)u.reg_read(X86Const.UC_X86_REG_RBX);
			rcx = (Long)u.reg_read(X86Const.UC_X86_REG_RCX);
			rdx = (Long)u.reg_read(X86Const.UC_X86_REG_RDX);
			rsi = (Long)u.reg_read(X86Const.UC_X86_REG_RSI);
			rdi = (Long)u.reg_read(X86Const.UC_X86_REG_RDI);
			r8 = (Long)u.reg_read(X86Const.UC_X86_REG_R8);
			r9 = (Long)u.reg_read(X86Const.UC_X86_REG_R9);
			r10 = (Long)u.reg_read(X86Const.UC_X86_REG_R10);
			r11 = (Long)u.reg_read(X86Const.UC_X86_REG_R11);
			r12 = (Long)u.reg_read(X86Const.UC_X86_REG_R12);
			r13 = (Long)u.reg_read(X86Const.UC_X86_REG_R13);
			r14 = (Long)u.reg_read(X86Const.UC_X86_REG_R14);
			r15 = (Long)u.reg_read(X86Const.UC_X86_REG_R15);
			rsp = (Long)u.reg_read(X86Const.UC_X86_REG_RSP);
			rbp = (Long)u.reg_read(X86Const.UC_X86_REG_RBP);
			rip = (Long)u.reg_read(X86Const.UC_X86_REG_RIP);}

		public int step_x64(byte[] CODE){
			//TODO add stack view somewhere

			//run current instruction
			int currentPC = getPC();
			// u.mem_write(currentPC, CODE);
			u.reg_write(X86Const.UC_X86_REG_RAX, (Long.parseLong(provider.UC_X86_REG_RAX.getText().substring(2), 16)));
			u.reg_write(X86Const.UC_X86_REG_RBX, (Long.parseLong(provider.UC_X86_REG_RBX.getText().substring(2), 16)));
			u.reg_write(X86Const.UC_X86_REG_RCX, (Long.parseLong(provider.UC_X86_REG_RCX.getText().substring(2), 16)));
			u.reg_write(X86Const.UC_X86_REG_RDX, (Long.parseLong(provider.UC_X86_REG_RDX.getText().substring(2), 16)));
			u.reg_write(X86Const.UC_X86_REG_RSI, (Long.parseLong(provider.UC_X86_REG_RSI.getText().substring(2), 16)));
			u.reg_write(X86Const.UC_X86_REG_RDI, (Long.parseLong(provider.UC_X86_REG_RDI.getText().substring(2), 16)));
			u.reg_write(X86Const.UC_X86_REG_R8, (Long.parseLong(provider.labelR8.getText().substring(2), 16)));
			u.reg_write(X86Const.UC_X86_REG_R9, (Long.parseLong(provider.labelR9.getText().substring(2), 16)));
			u.reg_write(X86Const.UC_X86_REG_R10, (Long.parseLong(provider.labelR10.getText().substring(2), 16)));
			u.reg_write(X86Const.UC_X86_REG_R11, (Long.parseLong(provider.labelR11.getText().substring(2), 16)));
			u.reg_write(X86Const.UC_X86_REG_R12, (Long.parseLong(provider.labelR12.getText().substring(2), 16)));
			u.reg_write(X86Const.UC_X86_REG_R13, (Long.parseLong(provider.labelR13.getText().substring(2), 16)));
			u.reg_write(X86Const.UC_X86_REG_R14, (Long.parseLong(provider.labelR14.getText().substring(2), 16)));
			u.reg_write(X86Const.UC_X86_REG_R15, ((Long.parseLong(provider.labelR15.getText().substring(2), 16))));
			u.reg_write(X86Const.UC_X86_REG_RSP, ((Long.parseLong(provider.UC_X86_REG_RSP.getText().substring(2), 16))));
			u.reg_write(X86Const.UC_X86_REG_RBP, ((Long.parseLong(provider.UC_X86_REG_RBP.getText().substring(2), 16))));
			u.reg_write(X86Const.UC_X86_REG_RIP, ((Long.parseLong(provider.UC_X86_REG_RIP.getText().substring(2), 16))));
			// for(byte b: CODE)
			// 	provider.addText(String.format("0x%x", b));
			provider.addText(String.format("Current 0x%x End 0x%x", currentPC, END));
			provider.addText("PRESTEP");
			u.emu_start(currentPC, END, 0, 1);
			provider.addText("POSTSTEP");
			if(currentPC == (int) END - 4) {
				status = -1;
			}
			printStats();
			return currentPC;
		}

		public int getPC() {
			Long currentPC = (Long) u.reg_read(X86Const.UC_X86_REG_RIP);
			return currentPC.intValue();}

		public int getStatus() {
			return status;
		}

		private void setRegs(String reg, String line) {
			int i = line.indexOf('x');
			if(reg == "RAX") {
				u.reg_write(X86Const.UC_X86_REG_RAX, Long.parseLong(line.substring(i + 1, line.length()), 16));
			}
			else if (reg == "RBX") {
				u.reg_write(X86Const.UC_X86_REG_RBX, Long.parseLong(line.substring(i + 1, line.length()), 16));
			}
			else if (reg == "RCX") {
				u.reg_write(X86Const.UC_X86_REG_RCX, Long.parseLong(line.substring(i + 1, line.length()), 16));
			}
			else if (reg == "RDX") {
				u.reg_write(X86Const.UC_X86_REG_RDX, Long.parseLong(line.substring(i + 1, line.length()), 16));
			}
			else if (reg == "RSI") {
				u.reg_write(X86Const.UC_X86_REG_RSI, Long.parseLong(line.substring(i + 1, line.length()), 16));
			}
			else if (reg == "RDI") {
				u.reg_write(X86Const.UC_X86_REG_RDI, Long.parseLong(line.substring(i + 1, line.length()), 16));
			}
			else if (reg == "R8") {
				u.reg_write(X86Const.UC_X86_REG_R8, Long.parseLong(line.substring(i + 1, line.length()), 16));
			}
			else if (reg == "R9") {
				u.reg_write(X86Const.UC_X86_REG_R9, Long.parseLong(line.substring(i + 1, line.length()), 16));
			}
			else if (reg == "R10") {
				u.reg_write(X86Const.UC_X86_REG_R10, Long.parseLong(line.substring(i + 1, line.length()), 16));
			}
			else if (reg == "R11") {
				u.reg_write(X86Const.UC_X86_REG_R11, Long.parseLong(line.substring(i + 1, line.length()), 16));
			}
			else if (reg == "R12") {
				u.reg_write(X86Const.UC_X86_REG_R12, Long.parseLong(line.substring(i + 1, line.length()), 16));
			}
			else if (reg == "R13") {
				u.reg_write(X86Const.UC_X86_REG_R13, Long.parseLong(line.substring(i + 1, line.length()), 16));
			}
			else if (reg == "R14") {
				u.reg_write(X86Const.UC_X86_REG_R14, Long.parseLong(line.substring(i + 1, line.length()), 16));
			}
			else if (reg == "R15") {
				u.reg_write(X86Const.UC_X86_REG_R15, Long.parseLong(line.substring(i + 1, line.length()), 16));
			}
			else if (reg == "RSP") {
				u.reg_write(X86Const.UC_X86_REG_RSP, Long.parseLong(line.substring(i + 1, line.length()), 16));
			}
			else if (reg == "RBP") {
				u.reg_write(X86Const.UC_X86_REG_RBP, Long.parseLong(line.substring(i + 1, line.length()), 16));
			}
			else if (reg == "RIP") {
				u.reg_write(X86Const.UC_X86_REG_RIP, Long.parseLong(line.substring(i + 1, line.length()), 16));
			}}

		public void printStats() {
			getRegs();

			provider.addText(String.format(">>> RAX = 0x%x", rax.intValue()));
			provider.addText(String.format(">>> RBX = 0x%x", rbx.intValue()));
			provider.addText(String.format(">>> RCX = 0x%x", rcx.intValue()));
			provider.addText(String.format(">>> RDX = 0x%x", rdx.intValue()));
			provider.addText(String.format(">>> RSI = 0x%x", rsi.intValue()));
			provider.addText(String.format(">>> RDI = 0x%x", rdi.intValue()));
			provider.addText(String.format(">>> R8 = 0x%x", r8.intValue()));
			provider.addText(String.format(">>> R9 = 0x%x", r9.intValue()));
			provider.addText(String.format(">>> R10 = 0x%x", r10.intValue()));
			provider.addText(String.format(">>> R11 = 0x%x", r11.intValue()));
			provider.addText(String.format(">>> R12 = 0x%x", r12.intValue()));
			provider.addText(String.format(">>> R13 = 0x%x", r13.intValue()));
			provider.addText(String.format(">>> R14 = 0x%x", r14.intValue()));
			provider.addText(String.format(">>> R15 = 0x%x", r15.intValue()));
			provider.addText(String.format(">>> RSP = 0x%x", rsp.intValue()));
			provider.addText(String.format(">>> RBP = 0x%x", rbp.intValue()));
			provider.addText(String.format(">>> RIP = 0x%x\n", rip.intValue()));

			provider.addText("========================");
			
			provider.UC_X86_REG_RAX.setText(String.format("0x%x", rax.intValue()));
			provider.UC_X86_REG_RBX.setText(String.format("0x%x", rbx.intValue()));
			provider.UC_X86_REG_RCX.setText(String.format("0x%x", rcx.intValue()));
			provider.UC_X86_REG_RDX.setText(String.format("0x%x", rdx.intValue()));
			provider.UC_X86_REG_RSI.setText(String.format("0x%x", rsi.intValue()));
			provider.UC_X86_REG_RDI.setText(String.format("0x%x", rdi.intValue()));
			provider.labelR8.setText(String.format("0x%x", r8.intValue()));
			provider.labelR9.setText(String.format("0x%x", r9.intValue()));
			provider.labelR10.setText(String.format("0x%x", r10.intValue()));
			provider.labelR11.setText(String.format("0x%x", r11.intValue()));
			provider.labelR12.setText(String.format("0x%x", r12.intValue()));
			provider.labelR13.setText(String.format("0x%x", r13.intValue()));
			provider.labelR14.setText(String.format("0x%x", r14.intValue()));
			provider.labelR15.setText(String.format("0x%x", r15.intValue()));
			provider.UC_X86_REG_RSP.setText(String.format("0x%x", rsp.intValue()));
			provider.UC_X86_REG_RBP.setText(String.format("0x%x", rbp.intValue()));
			provider.UC_X86_REG_RIP.setText(String.format("0x%x", rip.intValue()));

			//byte [] stack = u.mem_read(STACK - 0x100, 0x100);
			//byte [] memory = u.mem_read(BASE, BASE_MEMORY_SIZE);
			provider.clearStack();
			long stackPointer = STACK - 0x100;
			int i = 0;
			while(i < 0x20) {
				provider.setStack(String.format("0x%08x 0x", stackPointer));
				byte [] value = u.mem_read(stackPointer, 8);
				for(byte b: value)
					provider.setStack(String.format("%x", b));
				provider.setStack("\n");
				stackPointer = stackPointer + 8;
				i++;
			}
		}

		private class MyBlockHook implements BlockHook {
			public void hook(Unicorn uLoc, long address, int size, Object user_data){
		  		provider.addText(String.format(">>> Tracing basic block at 0x%x, block size = 0x%x\n", address, size));
			}}

		private class MyCodeHook implements CodeHook {
			public void hook(Unicorn uLoc, long address, int size, Object user_data) {
				// getRegs();
				// try {
				// 	String args = String.format("-RAX=%s -RBX=%s -RCX=%s -RDX=%s -RSI=%s -RDI=%s -R8=%s -R9=%s -R10=%s -R11=%s -R12=%s -R13=%s -R14=%s -R15=%s ",
				// 		Long.parseLong(provider.UC_X86_REG_RAX.getText().substring(2), 16), 
				// 		Long.parseLong(provider.UC_X86_REG_RBX.getText().substring(2), 16), 
				// 		Long.parseLong(provider.UC_X86_REG_RCX.getText().substring(2), 16), 
				// 		Long.parseLong(provider.UC_X86_REG_RDX.getText().substring(2), 16), 
				// 		Long.parseLong(provider.UC_X86_REG_RSI.getText().substring(2), 16), 
				// 		Long.parseLong(provider.UC_X86_REG_RDI.getText().substring(2), 16),  
				// 		Long.parseLong(provider.labelR8.getText().substring(2), 16), 
				// 		Long.parseLong(provider.labelR9.getText().substring(2), 16), 
				// 		Long.parseLong(provider.labelR10.getText().substring(2), 16), 
				// 		Long.parseLong(provider.labelR11.getText().substring(2), 16), 
				// 		Long.parseLong(provider.labelR12.getText().substring(2), 16),
				// 		Long.parseLong(provider.labelR13.getText().substring(2), 16), 
				// 		Long.parseLong(provider.labelR14.getText().substring(2), 16),
				// 		Long.parseLong(provider.labelR15.getText().substring(2), 16));
				// 	args = args + String.format("-ad=%s ", Long.toString(address));
				// 	args = args + String.format("-RSP=%s -RBP=%s -RIP=%s", 
				// 		Long.parseLong(provider.UC_X86_REG_RSP.getText().substring(2), 16), 
				// 		Long.parseLong(provider.UC_X86_REG_RBP.getText().substring(2), 16), 
				// 		Long.parseLong(provider.UC_X86_REG_RIP.getText().substring(2), 16)	);
				// 	String script = String.format("python3 ghidra_scripts/AddressHandler.py %s",args);
				// 	//provider.addText(script);
					
				// 	Process p = Runtime.getRuntime().exec(script);
				// 	BufferedReader stdInput = new BufferedReader(new InputStreamReader(p.getInputStream()));
				// 	String line = stdInput.readLine();
				// 	if(line != null) {
				// 		provider.addText("From AddressHandler.py Start====================");
				// 		while(line != null) {
				// 			provider.addText(line);

				// 			String reg = null;

				// 			if(line.contains("RAX")) {
				// 				reg = "RAX";
				// 			}
				// 			else if(line.contains("RBX")) {
				// 				reg = "RBX";
				// 			}
				// 			else if(line.contains("RCX")) {
				// 				reg = "RCX";
				// 			}
				// 			else if(line.contains("RDX")) {
				// 				reg = "RDX";
				// 			}
				// 			else if(line.contains("RSI")) {
				// 				reg = "RSI";
				// 			}
				// 			else if(line.contains("RDI")) {
				// 				reg = "RDI";
				// 			}
				// 			else if(line.contains("R8")) {
				// 				reg = "R8";
				// 			}
				// 			else if(line.contains("R9")) {
				// 				reg = "R9";
				// 			}
				// 			else if(line.contains("R10")) {
				// 				reg = "R10";
				// 			}
				// 			else if(line.contains("R11")) {
				// 				reg = "R11";
				// 			}
				// 			else if(line.contains("R12")) {
				// 				reg = "R12";
				// 			}
				// 			else if(line.contains("R13")) {
				// 				reg = "R13";
				// 			}
				// 			else if(line.contains("R14")) {
				// 				reg = "R14";
				// 			}
				// 			else if(line.contains("R15")) {
				// 				reg = "R15";
				// 			}
				// 			else if(line.contains("RSP")) {
				// 				reg = "RSP";
				// 			}
				// 			else if(line.contains("RBP")) {
				// 				reg = "RBP";
				// 			}
				// 			else if(line.contains("RIP")) {
				// 				reg = "RIP";
				// 			}
							
				// 			setRegs(reg,line);
				// 			line = stdInput.readLine();
				// 		}
				// 		provider.addText("From AddressHandler.py End====================");
				// 	}
					
				// } catch (IOException e) {
				// 	// TODO Auto-generated catch block
				// 	//e.printStackTrace();
				// }
				
					provider.addText(String.format(">>> Tracing instruction at 0x%x, instruction size = 0x%x", address, size));
					provider.addText(String.format(">>> Instruction = " + API.getInstructionContaining(API.toAddr(address)) + "\n"));
					printStats();
				}
		}

		private static class MyRead64Hook implements ReadHook {
      		public void hook(Unicorn u, long address, int size, Object user) {
         		provider.addText(String.format(">>> Memory READ at 0x%x, data size = %d, data value = 0x%s\n", 
         				address, size, u.mem_read(address, size)));
      		}
   		}

   		private static class MyWrite64Hook implements WriteHook {
      		public void hook(Unicorn u, long address, int size, long value, Object user) {
      			rsp = (Long)u.reg_read(X86Const.UC_X86_REG_RSP);
      			provider.addText(String.format(">>> RSP 0x%x\n", rsp));
         		provider.addText(String.format(">>> Memory WRITE at 0x%x, data size = %d, data value = 0x%x\n",
                	address, size, value));
      		}
   		}

		public byte[] getMemoryAtAddress(long address) {
			return u.mem_read(address, 4);
		}
}
