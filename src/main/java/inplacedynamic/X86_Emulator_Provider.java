package inplacedynamic;

import java.awt.Color;
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;

import javax.swing.*;
import javax.swing.border.BevelBorder;
import javax.swing.border.TitledBorder;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.*;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import resources.Icons;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;

public class X86_Emulator_Provider extends ComponentProviderAdapter{
	
	private X86_Emulator_Provider provider;
	private JPanel panel;
	private DockingAction action;
	private JTextArea emulator;
	private Address currentAddress;
	private long functionLen;
	private FunctionManager functionManager;
	private Function currentFunction;
	private X86_Emulator x64;
	private JTextArea stack;
	public JTextArea UC_X86_REG_RAX = new JTextArea();
	public JTextArea UC_X86_REG_RBX = new JTextArea();
	public JTextArea UC_X86_REG_RCX = new JTextArea();
	public JTextArea UC_X86_REG_RDX = new JTextArea();
	public JTextArea UC_X86_REG_RSI = new JTextArea();
	public JTextArea UC_X86_REG_RDI = new JTextArea();
	public JTextArea labelR8 = new JTextArea();
	public JTextArea labelR9 = new JTextArea();
	public JTextArea labelR10 = new JTextArea();
	public JTextArea labelR11 = new JTextArea();
	public JTextArea labelR12 = new JTextArea();
	public JTextArea labelR13 = new JTextArea();
	public JTextArea labelR14 = new JTextArea();
	public JTextArea labelR15 = new JTextArea();
	public JTextArea UC_X86_REG_RSP = new JTextArea();
	public JTextArea UC_X86_REG_RBP = new JTextArea();
	public JTextArea UC_X86_REG_RIP = new JTextArea();
	
	// rax - register a extended *
	// rbx - register b extended
	// rcx - register c extended
	// rdx - register d extended
	// rbp - register base pointer (start of stack)
	// rsp - register stack pointer (current location in stack, growing downwards) *
	// rsi - register source index (source for data copies)
	// rdi - register destination index (destination for data copies)
	// r8 - register 8
	// r9 - register 9
	// r10 - register 10
	// r11 - register 11
	// r12 - register 12
	// r13 - register 13
	// r14 - register 14
	// r15 - register 15

	
	public JTextArea base = new JTextArea();
	public JTextArea instru = new JTextArea();
	public JTextArea baseLen = new JTextArea();
	public JTextArea memoryView = new JTextArea();
	public JTextArea memoryLocation = new JTextArea();
	public JTextArea memoryContents = new JTextArea();
	private FlatProgramAPI api;
	
	public X86_Emulator_Provider(Plugin plugin, String owner) {
		super(plugin.getTool(), owner, owner);
		mkPanel();
		mkActions();
		tool = plugin.getTool();
		this.provider = this;
	}
	
	private void mkPanel(){
		TitledBorder border = new TitledBorder(new BevelBorder(BevelBorder.LOWERED), "RAX");
		UC_X86_REG_RAX.setBorder(border);
		UC_X86_REG_RAX.setEnabled(true);
		UC_X86_REG_RAX.setText("0x0000000000000000");
		
		border = new TitledBorder(new BevelBorder(BevelBorder.LOWERED), "RBX");
		UC_X86_REG_RBX.setEnabled(true);
		UC_X86_REG_RBX.setBorder(border);
		UC_X86_REG_RBX.setText("0x0000000000000000");
	
		border = new TitledBorder(new BevelBorder(BevelBorder.LOWERED), "RCX");
		UC_X86_REG_RCX.setEnabled(true);
		UC_X86_REG_RCX.setBorder(border);
		UC_X86_REG_RCX.setText("0x0000000000000000");
		
		border = new TitledBorder(new BevelBorder(BevelBorder.LOWERED), "RDX");
		UC_X86_REG_RDX.setEnabled(true);
		UC_X86_REG_RDX.setBorder(border);
		UC_X86_REG_RDX.setText("0x0000000000000000");
	
		border = new TitledBorder(new BevelBorder(BevelBorder.LOWERED), "RSI");
		UC_X86_REG_RSI.setEnabled(true);
		UC_X86_REG_RSI.setBorder(border);
		UC_X86_REG_RSI.setText("0x0000000000000000");
		
		border = new TitledBorder(new BevelBorder(BevelBorder.LOWERED), "RDI");
		UC_X86_REG_RDI.setEnabled(true);
		UC_X86_REG_RDI.setBorder(border);
		UC_X86_REG_RDI.setText("0x0000000000000000");
	
		border = new TitledBorder(new BevelBorder(BevelBorder.LOWERED), "R8");
		labelR8.setEnabled(true);
		labelR8.setBorder(border);
		labelR8.setText("0x0000000000000000");
	
		border = new TitledBorder(new BevelBorder(BevelBorder.LOWERED), "R9");
		labelR9.setEnabled(true);
		labelR9.setBorder(border);
		labelR9.setText("0x0000000000000000");
		
		border = new TitledBorder(new BevelBorder(BevelBorder.LOWERED), "R10");
		labelR10.setEnabled(true);
		labelR10.setBorder(border);
		labelR10.setText("0x0000000000000000");
		
		border = new TitledBorder(new BevelBorder(BevelBorder.LOWERED), "R11");
		labelR11.setEnabled(true);
		labelR11.setBorder(border);
		labelR11.setText("0x0000000000000000");
		
		border = new TitledBorder(new BevelBorder(BevelBorder.LOWERED), "R12");
		labelR12.setEnabled(true);
		labelR12.setBorder(border);
		labelR12.setText("0x0000000000000000");

		border = new TitledBorder(new BevelBorder(BevelBorder.LOWERED), "R13");
		labelR13.setEnabled(true);
		labelR13.setBorder(border);
		labelR13.setText("0x0000000000000000");
		
		border = new TitledBorder(new BevelBorder(BevelBorder.LOWERED), "R14");
		labelR14.setEnabled(true);
		labelR14.setBorder(border);
		labelR14.setText("0x0000000000000000");

		border = new TitledBorder(new BevelBorder(BevelBorder.LOWERED), "R15");
		labelR15.setEnabled(true);
		labelR15.setBorder(border);
		labelR15.setText("0x0000000000000000");
	
		border = new TitledBorder(new BevelBorder(BevelBorder.LOWERED), "RSP");
		UC_X86_REG_RSP.setEnabled(true);
		UC_X86_REG_RSP.setBorder(border);
		UC_X86_REG_RSP.setText("0xFFFF");
	
		border = new TitledBorder(new BevelBorder(BevelBorder.LOWERED), "RBP");
		UC_X86_REG_RBP.setEnabled(true);
		UC_X86_REG_RBP.setBorder(border);
		UC_X86_REG_RBP.setText("0x0000000000000000");
	
		border = new TitledBorder(new BevelBorder(BevelBorder.LOWERED), "RIP");
		UC_X86_REG_RIP.setEnabled(true);
		UC_X86_REG_RIP.setBorder(border);
		UC_X86_REG_RIP.setText("0x0000000000000000");

		border = new TitledBorder(new BevelBorder(BevelBorder.LOWERED), "BASE");
		base.setEnabled(true);
		base.setBorder(border);
		base.setText("0x100000");
		
		border = new TitledBorder(new BevelBorder(BevelBorder.LOWERED), "BASE_SIZE");
		baseLen.setEnabled(true);
		baseLen.setBorder(border);
		baseLen.setText("0x200000");
		
		border = new TitledBorder(new BevelBorder(BevelBorder.LOWERED), "NEXT INSTRUCTION");
		instru.setEnabled(true);
		instru.setBorder(border);
		instru.setText("00");

		JPanel insidePanel = new JPanel();
		insidePanel.setBorder(BorderFactory.createEmptyBorder(3, 3, 3, 3));
		insidePanel.setLayout(new BoxLayout(insidePanel, BoxLayout.Y_AXIS));
		insidePanel.add(UC_X86_REG_RAX);
		insidePanel.add(UC_X86_REG_RBX);
		insidePanel.add(UC_X86_REG_RCX);
		insidePanel.add(UC_X86_REG_RDX);
		insidePanel.add(UC_X86_REG_RSI);
		insidePanel.add(UC_X86_REG_RDI);
		insidePanel.add(labelR8);
		insidePanel.add(labelR9);
		insidePanel.add(labelR10);
		insidePanel.add(labelR11);
		insidePanel.add(labelR12);
		insidePanel.add(labelR13);
		insidePanel.add(labelR14);
		insidePanel.add(labelR15);
		insidePanel.add(UC_X86_REG_RSP);
		insidePanel.add(UC_X86_REG_RBP);
		insidePanel.add(UC_X86_REG_RIP);
		insidePanel.add(base);
		insidePanel.add(baseLen);

		panel = new JPanel();
		panel.setBorder(BorderFactory.createEmptyBorder(3, 3, 3, 3));
		panel.setLayout(new GridBagLayout());
		GridBagConstraints c = new GridBagConstraints();
		c.fill = GridBagConstraints.BOTH;
		
		c.gridx = 0;
		c.gridy = 0;
		c.weightx = 0.50;
		c.weighty = 0;
		//c.gridheight = 1;
		panel.add(instru, c);
		
		c.gridy = 1;
		c.weighty = 0.90;
		border = new TitledBorder(new BevelBorder(BevelBorder.LOWERED), "DEBUG VIEW");
		border.setTitleColor(Color.WHITE);
		emulator = new JTextArea();
		emulator.setBackground(Color.decode("#272822"));
		emulator.setForeground(Color.decode("#E6DB74"));
		emulator.setBorder(border);
		emulator.setEditable(false);
		JScrollPane scroll = new JScrollPane (emulator, ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED, 
				ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
		panel.add(scroll, c);
		
		//==============================================
		
		c.gridx = 1;
		c.weightx = 0.15;
		c.gridy = 0;
		c.weighty = 0;
		border = new TitledBorder(new BevelBorder(BevelBorder.LOWERED), "MEMORY LOCATION");
		memoryLocation.setEnabled(true);
		memoryLocation.setBorder(border);
		memoryLocation.setText("0xffffffff");
		panel.add(memoryLocation, c);
		
		c.gridx = 2;
		c.weightx = 0.15;
		c.gridy = 0;
		c.weighty = 0;
		border = new TitledBorder(new BevelBorder(BevelBorder.LOWERED), "MEMORY CONTENTS");
		memoryContents.setEnabled(true);
		memoryContents.setBorder(border);
		memoryContents.setText("00 00 00 00");
		panel.add(memoryContents, c);
		
		c.gridx = 1;
		c.gridy = 1;
		c.weighty = 0;
		c.gridwidth = 2;
		memoryView.setBackground(Color.decode("#272822"));
		memoryView.setForeground(Color.decode("#E6DB74"));
		memoryView.setEditable(false);
		border = new TitledBorder(new BevelBorder(BevelBorder.LOWERED), "MEMORY");
		border.setTitleColor(Color.WHITE);
		memoryView.setBorder(border);
		JScrollPane memoryScroll = new JScrollPane (memoryView, ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED, 
				ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
		panel.add(memoryScroll, c);
		
		
		//==============================================
		
		c.gridx = 3;
		c.gridy = 0;
		c.weightx = 0.10;
		c.gridheight = 2;
		c.gridwidth = 1;
		stack = new JTextArea();
		stack.setBackground(Color.decode("#272822"));
		stack.setForeground(Color.decode("#E6DB74"));
		stack.setEditable(false);
		border = new TitledBorder(new BevelBorder(BevelBorder.LOWERED), "STACK");
		border.setTitleColor(Color.WHITE);
		stack.setBorder(border);
		JScrollPane stackScroll = new JScrollPane (stack, ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED, 
				ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
		panel.add(stackScroll, c);
		
		//==============================================
		
		c.gridx = 4;
		c.gridy = 0;
		c.weightx = 0.10;
		c.gridheight = 2;
		JScrollPane lablesScroll = new JScrollPane (insidePanel, ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED, 
				ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
		panel.add(lablesScroll, c);

		setVisible(true);
	}

	private void mkActions() {
//		action = new DockingAction("Get Memory Address", getName()) {
//			@Override
//			public void actionPerformed(ActionContext context) {
//				Dimension d = instru.getSize();
//				emulator.append(String.format("%d, %d", d.width, d.height));
//				getMemoryContents();
//			}
//
//		};
//		
//		 action.setToolBarData(new ToolBarData(Icons.NAVIGATE_ON_INCOMING_EVENT_ICON, null));
//		 action.setEnabled(true);
//		 action.markHelpUnnecessary();
//		 dockingTool.addLocalAction(this, action);
		
		// action = new DockingAction("Set Memory Address", getName()) {
		// 	@Override
		// 	public void actionPerformed(ActionContext context) {
		// 		setMemoryContents();
		// 	}
		// };
		
		// action.setToolBarData(new ToolBarData(Icons.NAVIGATE_ON_OUTGOING_EVENT_ICON, null));
		// action.setEnabled(true);
		// action.markHelpUnnecessary();
		// dockingTool.addLocalAction(this, action);
		
		// action = new DockingAction("Set Bytes", getName()) {
		// 	@Override
		// 	public void actionPerformed(ActionContext context) {
		// 		if(arm != null) {
		// 			try {
		// 				String instruction = instru.getText();
		// 				byte [] newInstruction = {(byte) Integer.parseInt(instruction.substring(0, 2), 16), 
		// 					(byte) Integer.parseInt(instruction.substring(3, 5), 16),
		// 					(byte) Integer.parseInt(instruction.substring(6, 8), 16),
		// 					(byte) Integer.parseInt(instruction.substring(9, 11), 16)};
		// 					api.start();
		// 					Address nextAddress = api.toAddr(arm.getPC());
		// 					api.clearListing(nextAddress);
		// 					api.setBytes(nextAddress, newInstruction);
		// 					api.disassemble(nextAddress);
		// 					api.end(true);
		// 					// not sure if we need to auto analyze 
		// 					//api.analyzeChanges(currentFunction.getProgram());
		// 			} catch (MemoryAccessException e) {
		// 				// TODO Auto-generated catch block
		// 				e.printStackTrace();
		// 			} catch (CancelledException e) {
		// 				// TODO Auto-generated catch block
		// 				e.printStackTrace();
		// 			} catch (NumberFormatException e) {
		// 				Msg.showInfo(getClass(), null, "OPPS", String.format("Please format new instruction as: 01 02 03 04\n %s", e));
		// 			} catch (StringIndexOutOfBoundsException e) {
		// 				Msg.showInfo(getClass(), null, "OPPS", String.format("Please format new instruction as: 01 02 03 04\n %s", e));
		// 			}
		// 		}
		// 	}
		// };
		
		// action.setToolBarData(new ToolBarData(Icons.REFRESH_ICON, null));
		// action.setEnabled(true);
		// action.markHelpUnnecessary();
		// dockingTool.addLocalAction(this, action);
		
		// action = new DockingAction("Show Memory", getName()) {
		// 	@Override
		// 	public void actionPerformed(ActionContext context) {
		// 		updateMemory();
		// 	}
		// };
		
		// action.setToolBarData(new ToolBarData(Icons.EXPAND_ALL_ICON, null));
		// action.setEnabled(true);
		// action.markHelpUnnecessary();
		// dockingTool.addLocalAction(this, action);
		
		action = new DockingAction("Next Instruction", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				if(x64 != null) {
					byte[] code;
					try {
						//code = api.getBytes(api.toAddr(x64.getPC()), 4);
						
						Instruction in = api.getInstructionAt(api.toAddr(x64.getPC()));
						System.out.println(String.format("0x%x", x64.getPC()));
						for(byte b: in.getBytes())
							System.out.println(String.format("0x%x", b));
						
						code = in.getBytes();
										
						setCurrentAddress(api.toAddr(x64.step_x64(code)), currentFunction.getProgram());
						System.out.println(String.format(in.getNext().getAddress().toString()));
						UC_X86_REG_RIP.setText(in.getNext().getAddress().toString());
						instru.setText(in.getNext().getAddress().toString());
						//updateMemory();
					} catch (MemoryAccessException e) {
						Msg.showInfo(getClass(), null, "OPPS", e);
					}
					if(x64.getStatus() != 1) {
						x64 = null;
						Msg.showInfo(getClass(), null, "Finished", "Program Emulation Finished");
					}
				}
			}
		};
		
		action.setToolBarData(new ToolBarData(Icons.ARROW_DOWN_RIGHT_ICON, null));
		action.setEnabled(true);
		action.markHelpUnnecessary();
		dockingTool.addLocalAction(this, action);
		
		// action = new DockingAction("Run", getName()) {
		// 	@Override
		// 	public void actionPerformed(ActionContext context) {
		// 		if(arm != null) {
		// 			setCurrentAddress(api.toAddr(arm.run_arm()), currentFunction.getProgram());
		// 			arm = null;
		// 			//step = false;
		// 			Msg.showInfo(getClass(), null, "Finished", "Program Emulation Finished");
		// 		}
		// 		else {
		// 			Msg.showInfo(getClass(), null, "Start", "Please setup current function to run");
		// 		}
		// 	}
		// };
		
		// action.setToolBarData(new ToolBarData(Icons.RIGHT_ICON, null));
		// action.setEnabled(true);
		// action.markHelpUnnecessary();
		// dockingTool.addLocalAction(this, action);
		
		 action = new DockingAction("Emulate Current Function", getName()) {
		 	@Override
		 	public void actionPerformed(ActionContext context) {
		 		emulator.setText("");
		 		clearStack();
		 		currentFunction = functionManager.getFunctionContaining(currentAddress);
		 		Address lastAddress = currentAddress.add(4);
		 		if(currentFunction != null) {
		 			while(currentFunction.equals(functionManager.getFunctionContaining(lastAddress.add(4)))) {
		 				lastAddress = lastAddress.add(4);
		 			}
		 			currentAddress = currentFunction.getEntryPoint();
		 			functionLen = lastAddress.subtract(currentAddress);
		 			api = new FlatProgramAPI(currentFunction.getProgram());
		 			byte[] code;
		 			try {
		 				code = api.getBytes(currentAddress, (int) functionLen);
		 				x64 = new X86_Emulator(provider, Integer.parseInt(currentAddress.toString(), 16), code, api);
		 			} catch (MemoryAccessException e) {
		 				// TODO Auto-generated catch block
		 				e.printStackTrace();
		 			}
		 		}
		 	}
		 };
		 action.setToolBarData(new ToolBarData(Icons.ADD_ICON, null));
		 action.setEnabled(true);
		 dockingTool.addLocalAction(this, action);
		
		 // clear current emulation
		 action = new DockingAction("Clear", getName()) {
		 	@Override
		 	public void actionPerformed(ActionContext context) {
		 		x64 = null;
		 		//step = false;
		 		emulator.setText("");
		 		clearStack();
		 		UC_X86_REG_RAX.setText("0x0000000000000000");
		 		UC_X86_REG_RBX.setText("0x0000000000000000");
		 		UC_X86_REG_RCX.setText("0x0000000000000000");
		 		UC_X86_REG_RDX.setText("0x0000000000000000");
		 		UC_X86_REG_RSI.setText("0x0000000000000000");
		 		UC_X86_REG_RDI.setText("0x0000000000000000");
		 		labelR8.setText("0x0000000000000000");
		 		labelR9.setText("0x0000000000000000");
		 		labelR10.setText("0x0000000000000000");
		 		labelR11.setText("0x0000000000000000");
		 		labelR12.setText("0x0000000000000000");
		 		labelR13.setText("0x0000000000000000");
		 		labelR14.setText("0x0000000000000000");
		 		labelR15.setText("0x0000000000000000");
		 		UC_X86_REG_RSP.setText("0xF0000000");
		 		UC_X86_REG_RBP.setText("0x0000000000000000");
		 		UC_X86_REG_RIP.setText("0x0000000000000000");
		 		base.setText("0x100000");
		 	}
		 };
		 action.setToolBarData(new ToolBarData(Icons.DELETE_ICON, null));
		 action.setEnabled(true);
		 action.markHelpUnnecessary();
		 dockingTool.addLocalAction(this, action);
	}	

	public void clearStack() {
		stack.setText("");
	}

	public void setStack(String st) {
		stack.append(st);
	}

	public void setLocation(ProgramLocation location, Program program) {
		currentAddress = location.getAddress();
		functionManager = program.getFunctionManager();
	}
	
//	private void getMemoryContents() {
//		if(x64 != null) {
//			memoryContents.setText("");
//			long MemoryLocation = Long.parseLong(memoryLocation.getText().substring(2), 16);
//			byte [] memory = x64.getMemoryAtAddress(MemoryLocation);
//			memoryContents.append(String.format("%02x %02x %02x %02x", memory[0], memory[1], memory[2], memory[3]));
//		}
//	}
	
	public void addText(String newText) {
		emulator.append(newText + "\n\r");
	}
	
	private void setCurrentAddress(Address addr, Program pg) {
		GoToService goToService = tool.getService(GoToService.class);
		goToService.goTo(addr, pg);
	}
	
	@Override
	public JComponent getComponent() {
		return panel;
	}
	
	public long getBase() {
		return Long.parseLong(base.getText().substring(2), 16);
	}
	
	public long getBaseLen() {
		return Long.parseLong(baseLen.getText().substring(2), 16);
	}
}
