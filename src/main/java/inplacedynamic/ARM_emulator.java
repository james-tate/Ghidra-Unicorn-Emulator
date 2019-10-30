package inplacedynamic;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

import ghidra.program.flatapi.FlatProgramAPI;
import unicorn.*;

public class ARM_emulator {

	private static ARM_Emulator_Provider provider;
	public static long ADDRESS;
	public static long END;
	public static long BASE = 0x10000;
	public static long BASE_MEMORY_SIZE = 2 * 1024 * 1024;
	public static long STACK = 0x0000;
	public static long WORKING = 0x50000;
	public static long STACK_SIZE = 2 * 1024;
	private static FlatProgramAPI API;
	public static byte[] ARM_CODE;
	private static int status;
	private static Unicorn u;
	public static Long r0;
	public static Long r1;
	public static Long r2;
	public static Long r3;
	public static Long r4;
	public static Long r5;
	public static Long r6;
	public static Long r7;
	public static Long r8;
	public static Long r9;
	public static Long r10;
	public static Long r11;
	public static Long r12;
	public static Long sp;
	public static Long lr;
	public static Long pc;
	public static Long cpsr;

	public ARM_emulator(ARM_Emulator_Provider pr, long address, byte[] code, FlatProgramAPI api){
		ARM_CODE = code;
		provider = pr;
		ADDRESS = address;
		API = api;
		BASE = provider.getBase();
		BASE_MEMORY_SIZE = provider.getBaseLen();
		END = ADDRESS + ARM_CODE.length;
		
		// add function number or name
		provider.addText(String.format("Emulate ARM code at function 0x%x with end 0x%x\n", ADDRESS, END));

		// Initialize emulator in ARM mode
		u = new Unicorn(UnicornConst.UC_ARCH_ARM, UnicornConst.UC_MODE_ARM);

		// map 2MB memory for this emulation
		u.mem_map(BASE, BASE_MEMORY_SIZE, UnicornConst.UC_PROT_ALL);
		// stack
		u.mem_map(STACK, STACK_SIZE, UnicornConst.UC_PROT_ALL);
		//System.out.println(u.mem_regions());

		// write machine code to be emulated to memory
		u.mem_write(ADDRESS, ARM_CODE);
		
		// initialize machine registers
		u.reg_write(ArmConst.UC_ARM_REG_R0, (Long.parseLong(provider.labelR0.getText().substring(2), 16)));
		u.reg_write(ArmConst.UC_ARM_REG_R1, (Long.parseLong(provider.labelR1.getText().substring(2), 16)));
		u.reg_write(ArmConst.UC_ARM_REG_R2, (Long.parseLong(provider.labelR2.getText().substring(2), 16)));
		u.reg_write(ArmConst.UC_ARM_REG_R3, (Long.parseLong(provider.labelR3.getText().substring(2), 16)));
		u.reg_write(ArmConst.UC_ARM_REG_R4, (Long.parseLong(provider.labelR4.getText().substring(2), 16)));
		u.reg_write(ArmConst.UC_ARM_REG_R5, (Long.parseLong(provider.labelR5.getText().substring(2), 16)));
		u.reg_write(ArmConst.UC_ARM_REG_R6, (Long.parseLong(provider.labelR6.getText().substring(2), 16)));
		u.reg_write(ArmConst.UC_ARM_REG_R7, (Long.parseLong(provider.labelR7.getText().substring(2), 16)));
		u.reg_write(ArmConst.UC_ARM_REG_R8, (Long.parseLong(provider.labelR8.getText().substring(2), 16)));
		u.reg_write(ArmConst.UC_ARM_REG_R9, (Long.parseLong(provider.labelR9.getText().substring(2), 16)));
		u.reg_write(ArmConst.UC_ARM_REG_R10, (Long.parseLong(provider.labelR10.getText().substring(2), 16)));
		u.reg_write(ArmConst.UC_ARM_REG_R11, (Long.parseLong(provider.labelR11.getText().substring(2), 16)));
		u.reg_write(ArmConst.UC_ARM_REG_R12, (Long.parseLong(provider.labelR12.getText().substring(2), 16)));
		u.reg_write(ArmConst.UC_ARM_REG_SP, ((Long.parseLong(provider.labelSP.getText().substring(2), 16))));
		u.reg_write(ArmConst.UC_ARM_REG_LR, ((Long.parseLong(provider.labelLR.getText().substring(2), 16))));
		u.reg_write(ArmConst.UC_ARM_REG_PC, ADDRESS);
		u.reg_write(ArmConst.UC_ARM_REG_CPSR, ((Long.parseLong(provider.labelCPSR.getText().substring(2), 16))));
		
		pc = (Long)u.reg_read(ArmConst.UC_ARM_REG_PC);
		provider.labelPC.setText(String.format("0x%x", pc.intValue()));

		// tracing all basic blocks with customized callback
		u.hook_add(new MyBlockHook(), 1, 0, null);

		// tracing one instruction at ADDRESS with customized callback
		u.hook_add(new MyCodeHook(), ADDRESS, ADDRESS, null);
		
		status = 1;}
	
	//constructor for scripting
	public ARM_emulator(long address, byte[] code, long[] regs){
		//TODO pass in R Values using array
		ARM_CODE = code;
		ADDRESS = address;
		END = ADDRESS + ARM_CODE.length;

		u = new Unicorn(UnicornConst.UC_ARCH_ARM, UnicornConst.UC_MODE_ARM);
		u.mem_map(BASE, BASE_MEMORY_SIZE, UnicornConst.UC_PROT_ALL);
		u.mem_map(STACK, STACK_SIZE, UnicornConst.UC_PROT_ALL);
		u.mem_write(ADDRESS, ARM_CODE);
		u.reg_write(ArmConst.UC_ARM_REG_PC, ADDRESS);
		u.reg_write(ArmConst.UC_ARM_REG_R0, regs[0]);
		u.reg_write(ArmConst.UC_ARM_REG_R1, regs[1]);
		u.reg_write(ArmConst.UC_ARM_REG_R2, regs[2]);
		u.reg_write(ArmConst.UC_ARM_REG_R3, regs[3]);
		u.reg_write(ArmConst.UC_ARM_REG_R4, regs[4]);
		u.reg_write(ArmConst.UC_ARM_REG_R5, regs[5]);
		u.reg_write(ArmConst.UC_ARM_REG_R6, regs[6]);
		u.reg_write(ArmConst.UC_ARM_REG_R7, regs[7]);
		u.reg_write(ArmConst.UC_ARM_REG_R8, regs[8]);
		u.reg_write(ArmConst.UC_ARM_REG_R9, regs[9]);
		u.reg_write(ArmConst.UC_ARM_REG_R10, regs[10]);
		u.reg_write(ArmConst.UC_ARM_REG_R11, regs[11]);
		u.reg_write(ArmConst.UC_ARM_REG_R12, regs[12]);
		u.reg_write(ArmConst.UC_ARM_REG_SP, 0x800);

		//		// TODO: add hooks for scripting
		//		//u.hook_add(new MyBlockHook(), 1, 0, null);
	//
	//		// tracing one instruction at ADDRESS with customized callback
	//		//u.hook_add(new MyCodeHook(), ADDRESS, ADDRESS, null);
		u.emu_start(ADDRESS, END, 0, 0);
	//		//TODO // add public variables to send to python
   		
   		//this crashes for some reason
		//close_arm();
	}

	private class MyBlockHook implements BlockHook {
	  	public void hook(Unicorn uLoc, long address, int size, Object user_data)
	  	{
	      	provider.addText(String.format(">>> Tracing basic block at 0x%x, block size = 0x%x\n", address, size));
	  	}
	}
	  
	// callback for tracing instruction
	private class MyCodeHook implements CodeHook {
		public void hook(Unicorn uLoc, long address, int size, Object user_data) {
			getRegs();
			try {
				String args = String.format("-R0=%s -R1=%s -R2=%s -R3=%s -R4=%s -R5=%s -R6=%s -R7=%s -R8=%s -R9=%s -R10=%s -R11=%s -R12=%s ",
					Long.parseLong(provider.labelR0.getText().substring(2), 16), Long.parseLong(provider.labelR1.getText().substring(2), 16), Long.parseLong(provider.labelR2.getText().substring(2), 16), Long.parseLong(provider.labelR3.getText().substring(2), 16), Long.parseLong(provider.labelR4.getText().substring(2), 16), Long.parseLong(provider.labelR5.getText().substring(2), 16), 
					Long.parseLong(provider.labelR6.getText().substring(2), 16), Long.parseLong(provider.labelR7.getText().substring(2), 16), Long.parseLong(provider.labelR8.getText().substring(2), 16), Long.parseLong(provider.labelR9.getText().substring(2), 16), Long.parseLong(provider.labelR10.getText().substring(2), 16), Long.parseLong(provider.labelR11.getText().substring(2), 16), Long.parseLong(provider.labelR12.getText().substring(2), 16));
				args = args + String.format("-ad=%s ", Long.toString(address));
				args = args + String.format("-sp=%s -lr=%s -pc=%s -cpsr=%s", Long.parseLong(provider.labelSP.getText().substring(2), 16), Long.parseLong(provider.labelLR.getText().substring(2), 16), Long.parseLong(provider.labelPC.getText().substring(2), 16), Long.parseLong(provider.labelCPSR.getText().substring(2), 16));
				String script = String.format("python3 ghidra_scripts/AddressHandler.py %s",args);
				//provider.addText(script);
				
				Process p = Runtime.getRuntime().exec(script);
				BufferedReader stdInput = new BufferedReader(new InputStreamReader(p.getInputStream()));
				String line = stdInput.readLine();
				if(line != null) {
					provider.addText("From AddressHandler.py Start====================");
					while(line != null) {
						provider.addText(line);
					
						String reg = null;
						if(line.contains("R0")) {
							reg = "R0";
						}
						else if(line.contains("R1")) {
							reg = "R1";
						}
						else if(line.contains("R2")) {
							reg = "R2";
						}
						else if(line.contains("R3")) {
							reg = "R3";
						}
						else if(line.contains("R4")) {
							reg = "R4";
						}
						else if(line.contains("R5")) {
							reg = "R5";
						}
						else if(line.contains("R6")) {
							reg = "R6";
						}
						else if(line.contains("R7")) {
							reg = "R7";
						}
						else if(line.contains("R8")) {
							reg = "R8";
						}
						else if(line.contains("R9")) {
							reg = "R9";
						}
						else if(line.contains("R10")) {
							reg = "R10";
						}
						else if(line.contains("R11")) {
							reg = "R11";
						}
						else if(line.contains("R12")) {
							reg = "R12";
						}
						else if(line.contains("SP")) {
							reg = "SP";
						}
						else if(line.contains("LR")) {
							reg = "LR";
						}
						else if(line.contains("PC")) {
							reg = "PC";
						}
						else if(line.contains("CPSR")) {
							reg = "CPSR";
						}
						setRegs(reg,line);
						line = stdInput.readLine();
					}
					provider.addText("From AddressHandler.py End====================");
				}
				
			} catch (IOException e) {
				// TODO Auto-generated catch block
				//e.printStackTrace();
			}
			
	   		provider.addText(String.format(">>> Tracing instruction at 0x%x, instruction size = 0x%x", address, size));
	   		provider.addText(String.format(">>> Instruction = " + API.getInstructionContaining(API.toAddr(address)) + "\n"));
	   		printStats();
	  	}
	}

	public int run_arm(){
		u.emu_start(ADDRESS, END, 0, 0);
		provider.addText(">>> Emulation done. ");
		printStats();
		close_arm();
		status = -1;
		return (int) Long.parseLong(provider.labelPC.getText().substring(2), 16);
	}
	
	public int step_arm(byte[] CODE){
		//TODO add stack view somewhere
		
		
		
		//run current instruction
		int currentPC = getPC();
		u.mem_write(currentPC, CODE);
		u.reg_write(ArmConst.UC_ARM_REG_R0, (Long.parseLong(provider.labelR0.getText().substring(2), 16)));
		u.reg_write(ArmConst.UC_ARM_REG_R1, (Long.parseLong(provider.labelR1.getText().substring(2), 16)));
		u.reg_write(ArmConst.UC_ARM_REG_R2, (Long.parseLong(provider.labelR2.getText().substring(2), 16)));
		u.reg_write(ArmConst.UC_ARM_REG_R3, (Long.parseLong(provider.labelR3.getText().substring(2), 16)));
		u.reg_write(ArmConst.UC_ARM_REG_R4, (Long.parseLong(provider.labelR4.getText().substring(2), 16)));
		u.reg_write(ArmConst.UC_ARM_REG_R5, (Long.parseLong(provider.labelR5.getText().substring(2), 16)));
		u.reg_write(ArmConst.UC_ARM_REG_R6, (Long.parseLong(provider.labelR6.getText().substring(2), 16)));
		u.reg_write(ArmConst.UC_ARM_REG_R7, (Long.parseLong(provider.labelR7.getText().substring(2), 16)));
		u.reg_write(ArmConst.UC_ARM_REG_R8, (Long.parseLong(provider.labelR8.getText().substring(2), 16)));
		u.reg_write(ArmConst.UC_ARM_REG_R9, (Long.parseLong(provider.labelR9.getText().substring(2), 16)));
		u.reg_write(ArmConst.UC_ARM_REG_R10, (Long.parseLong(provider.labelR10.getText().substring(2), 16)));
		u.reg_write(ArmConst.UC_ARM_REG_R11, (Long.parseLong(provider.labelR11.getText().substring(2), 16)));
		u.reg_write(ArmConst.UC_ARM_REG_R12, (Long.parseLong(provider.labelR12.getText().substring(2), 16)));
		u.reg_write(ArmConst.UC_ARM_REG_SP, ((Long.parseLong(provider.labelSP.getText().substring(2), 16))));
		u.reg_write(ArmConst.UC_ARM_REG_LR, ((Long.parseLong(provider.labelLR.getText().substring(2), 16))));
		u.reg_write(ArmConst.UC_ARM_REG_PC, ((Long.parseLong(provider.labelPC.getText().substring(2), 16))));
		u.reg_write(ArmConst.UC_ARM_REG_CPSR, ((Long.parseLong(provider.labelCPSR.getText().substring(2), 16))));
//		for(byte b: CODE)
//			System.out.println(String.format("0x%x", b));
		//System.out.println(String.format("0x%x 0x%x", currentPC, END));
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
		Long currentPC = (Long) u.reg_read(ArmConst.UC_ARM_REG_PC);
		return currentPC.intValue();
	}
	
	public int getStatus() {
		return status;
	}

	public void close_arm() {
		try {
			u.close();
		}
		catch (UnicornException e) {
			//TODO: add something here
		}
	}

	public void printStats() {
		getRegs();
   		provider.addText(String.format(">>> R0 = 0x%x", r0.intValue()));
	 	provider.addText(String.format(">>> R1 = 0x%x", r1.intValue()));
	 	provider.addText(String.format(">>> R2 = 0x%x", r2.intValue()));
	 	provider.addText(String.format(">>> R3 = 0x%x", r3.intValue()));
	 	provider.addText(String.format(">>> R4 = 0x%x", r4.intValue()));
	 	provider.addText(String.format(">>> R5 = 0x%x", r5.intValue()));
	 	provider.addText(String.format(">>> R6 = 0x%x", r6.intValue()));
	 	provider.addText(String.format(">>> R7 = 0x%x", r7.intValue()));
	 	provider.addText(String.format(">>> R8 = 0x%x", r8.intValue()));
	 	provider.addText(String.format(">>> R9 = 0x%x", r9.intValue()));
	 	provider.addText(String.format(">>> R10 = 0x%x", r10.intValue()));
	 	provider.addText(String.format(">>> R11 = 0x%x", r11.intValue()));
	 	provider.addText(String.format(">>> R12 = 0x%x", r12.intValue()));
	 	provider.addText(String.format(">>> SP = 0x%x", sp.intValue()));
	 	provider.addText(String.format(">>> LR = 0x%x", lr.intValue()));
	 	provider.addText(String.format(">>> PC = 0x%x", pc.intValue()));
	 	provider.addText(String.format(">>> CPSR = 0x%x\n", cpsr.intValue()));
	 	provider.addText("========================");
	 	provider.labelR0.setText(String.format("0x%x", r0.intValue()));
	 	provider.labelR1.setText(String.format("0x%x", r1.intValue()));
	 	provider.labelR2.setText(String.format("0x%x", r2.intValue()));
	 	provider.labelR3.setText(String.format("0x%x", r3.intValue()));
	 	provider.labelR4.setText(String.format("0x%x", r4.intValue()));
	 	provider.labelR5.setText(String.format("0x%x", r5.intValue()));
	 	provider.labelR6.setText(String.format("0x%x", r6.intValue()));
	 	provider.labelR7.setText(String.format("0x%x", r7.intValue()));
	 	provider.labelR8.setText(String.format("0x%x", r8.intValue()));
	 	provider.labelR9.setText(String.format("0x%x", r9.intValue()));
	 	provider.labelR10.setText(String.format("0x%x", r10.intValue()));
	 	provider.labelR11.setText(String.format("0x%x", r11.intValue()));
	 	provider.labelR12.setText(String.format("0x%x", r12.intValue()));
	 	provider.labelSP.setText(String.format("0x%x", sp.intValue()));
	 	provider.labelLR.setText(String.format("0x%x", lr.intValue()));
	 	provider.labelPC.setText(String.format("0x%x", pc.intValue()));
	 	provider.labelCPSR.setText(String.format("0x%x", cpsr.intValue()));
	 	byte [] stack = u.mem_read(STACK, STACK_SIZE);
	 	//byte [] memory = u.mem_read(BASE, BASE_MEMORY_SIZE);
	 	provider.clearStack();
	 	int stackPointer = 0;
	 	while(stackPointer < stack.length) {
	 		provider.setStack(String.format("0x%04x 0x%x%x\n", stackPointer, stack[stackPointer + 1], stack[stackPointer]));
	 		stackPointer = stackPointer + 4;
	 	}
	}
	
	public void getRegs() {
		r0 = (Long)u.reg_read(ArmConst.UC_ARM_REG_R0);
   		r1 = (Long)u.reg_read(ArmConst.UC_ARM_REG_R1);
   		r2 = (Long)u.reg_read(ArmConst.UC_ARM_REG_R2);
   		r3 = (Long)u.reg_read(ArmConst.UC_ARM_REG_R3);
   		r4 = (Long)u.reg_read(ArmConst.UC_ARM_REG_R4);
   		r5 = (Long)u.reg_read(ArmConst.UC_ARM_REG_R5);
   		r6 = (Long)u.reg_read(ArmConst.UC_ARM_REG_R6);
   		r7 = (Long)u.reg_read(ArmConst.UC_ARM_REG_R7);
   		r8 = (Long)u.reg_read(ArmConst.UC_ARM_REG_R8);
   		r9 = (Long)u.reg_read(ArmConst.UC_ARM_REG_R9);
   		r10 = (Long)u.reg_read(ArmConst.UC_ARM_REG_R10);
   		r11 = (Long)u.reg_read(ArmConst.UC_ARM_REG_R11);
   		r12 = (Long)u.reg_read(ArmConst.UC_ARM_REG_R12);
   		sp = (Long)u.reg_read(ArmConst.UC_ARM_REG_SP);
   		lr = (Long)u.reg_read(ArmConst.UC_ARM_REG_LR);
   		pc = (Long)u.reg_read(ArmConst.UC_ARM_REG_PC);
   		cpsr = (Long)u.reg_read(ArmConst.UC_ARM_REG_CPSR);
	}
	
	public byte[] getMemory() {
		return u.mem_read(BASE, BASE_MEMORY_SIZE);
	}
	
	public byte[] getMemoryAtAddress(long address) {
		return u.mem_read(address, 4);
	}
	
	public void setMemoryAtAddress(long address, byte[] code) {
		u.mem_write(address, code);
	}
	
	public long getBase() {
		return BASE;
	}

	private void setRegs(String reg, String line) {
		int i = line.indexOf('x');
		if(reg == "R0") {
			u.reg_write(ArmConst.UC_ARM_REG_R0, Long.parseLong(line.substring(i + 1, line.length()), 16));
		}
		else if (reg == "R1") {
			u.reg_write(ArmConst.UC_ARM_REG_R1, Long.parseLong(line.substring(i + 1, line.length()), 16));
		}
		else if (reg == "R2") {
			u.reg_write(ArmConst.UC_ARM_REG_R2, Long.parseLong(line.substring(i + 1, line.length()), 16));
		}
		else if (reg == "R3") {
			u.reg_write(ArmConst.UC_ARM_REG_R3, Long.parseLong(line.substring(i + 1, line.length()), 16));
		}
		else if (reg == "R4") {
			u.reg_write(ArmConst.UC_ARM_REG_R4, Long.parseLong(line.substring(i + 1, line.length()), 16));
		}
		else if (reg == "R5") {
			u.reg_write(ArmConst.UC_ARM_REG_R5, Long.parseLong(line.substring(i + 1, line.length()), 16));
		}
		else if (reg == "R6") {
			u.reg_write(ArmConst.UC_ARM_REG_R6, Long.parseLong(line.substring(i + 1, line.length()), 16));
		}
		else if (reg == "R7") {
			u.reg_write(ArmConst.UC_ARM_REG_R7, Long.parseLong(line.substring(i + 1, line.length()), 16));
		}
		else if (reg == "R8") {
			u.reg_write(ArmConst.UC_ARM_REG_R8, Long.parseLong(line.substring(i + 1, line.length()), 16));
		}
		else if (reg == "R9") {
			u.reg_write(ArmConst.UC_ARM_REG_R9, Long.parseLong(line.substring(i + 1, line.length()), 16));
		}
		else if (reg == "R10") {
			u.reg_write(ArmConst.UC_ARM_REG_R10, Long.parseLong(line.substring(i + 1, line.length()), 16));
		}
		else if (reg == "R11") {
			u.reg_write(ArmConst.UC_ARM_REG_R11, Long.parseLong(line.substring(i + 1, line.length()), 16));
		}
		else if (reg == "R12") {
			u.reg_write(ArmConst.UC_ARM_REG_R12, Long.parseLong(line.substring(i + 1, line.length()), 16));
		}
		else if (reg == "SP") {
			u.reg_write(ArmConst.UC_ARM_REG_SP, Long.parseLong(line.substring(i + 1, line.length()), 16));
		}
		else if (reg == "LR") {
			u.reg_write(ArmConst.UC_ARM_REG_LR, Long.parseLong(line.substring(i + 1, line.length()), 16));
		}
		else if (reg == "PC") {
			u.reg_write(ArmConst.UC_ARM_REG_PC, Long.parseLong(line.substring(i + 1, line.length()), 16));
		}
		else if (reg == "CPSR") {
			u.reg_write(ArmConst.UC_ARM_REG_CPSR, Long.parseLong(line.substring(i + 1, line.length()), 16));
		}
	}

	public int getRegValue(String reg) {
		Long regValue = null;
		switch(reg) {
		case "R0":
			regValue = (Long)u.reg_read(ArmConst.UC_ARM_REG_R0);
			break;
		case "R1":
			regValue = (Long)u.reg_read(ArmConst.UC_ARM_REG_R1);
			break;
		case "R2":
			regValue = (Long)u.reg_read(ArmConst.UC_ARM_REG_R2);
			break;
		case "R3":
			regValue = (Long)u.reg_read(ArmConst.UC_ARM_REG_R3);
			break;
		case "R4":
			regValue = (Long)u.reg_read(ArmConst.UC_ARM_REG_R4);
			break;
		case "R5":
			regValue = (Long)u.reg_read(ArmConst.UC_ARM_REG_R5);
			break;
		case "R6":
			regValue = (Long)u.reg_read(ArmConst.UC_ARM_REG_R6);
			break;
		case "R7":
			regValue = (Long)u.reg_read(ArmConst.UC_ARM_REG_R7);
			break;
		case "R8":
			regValue = (Long)u.reg_read(ArmConst.UC_ARM_REG_R8);
			break;
		case "R9":
			regValue = (Long)u.reg_read(ArmConst.UC_ARM_REG_R9);
			break;
		case "R10":
			regValue = (Long)u.reg_read(ArmConst.UC_ARM_REG_R10);
			break;
		case "R11":
			regValue = (Long)u.reg_read(ArmConst.UC_ARM_REG_R11);
			break;
		case "R12":
			regValue = (Long)u.reg_read(ArmConst.UC_ARM_REG_R12);
			break;
		case "SP":
			regValue = (Long)u.reg_read(ArmConst.UC_ARM_REG_SP);
			break;
		case "LR":
			regValue = (Long)u.reg_read(ArmConst.UC_ARM_REG_LR);
			break;
		case "CPSR":
			regValue = (Long)u.reg_read(ArmConst.UC_ARM_REG_CPSR);
			break;
		case "PC":
			regValue = (Long)u.reg_read(ArmConst.UC_ARM_REG_PC);
			break;
		default:
			regValue = null;
		}
		return regValue.intValue();
	}
}
